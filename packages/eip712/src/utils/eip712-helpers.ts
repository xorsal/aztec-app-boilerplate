/**
 * EIP-712 Helper Utilities
 *
 * Helper functions for building EIP-712 transaction context from contract interactions.
 */

import type {
  ContractArtifact,
  FunctionArtifact,
  ABIParameter,
  AbiType,
} from "@aztec/aztec.js/abi";
import type { AztecAddress } from "@aztec/aztec.js/addresses";
import { FunctionSelector } from "@aztec/stdlib/abi";
import type { FunctionCallInput } from "../lib/index";

/**
 * Convert a Noir type to a human-readable type string for function signatures.
 *
 * @param param - The ABI parameter
 * @returns Human-readable type string
 */
export function noirTypeToString(param: ABIParameter): string {
  const { type } = param;

  // Handle basic types
  if (typeof type === "string") {
    return type;
  }

  // Handle structured types
  switch (type.kind) {
    case "field":
      return "Field";
    case "integer":
      return type.sign === "unsigned" ? `u${type.width}` : `i${type.width}`;
    case "boolean":
      return "bool";
    case "string":
      // Aztec uses str<length> format
      return `str<${type.length}>`;
    case "array":
      // For arrays, recursively convert the element type
      // Note: Aztec uses [Type;length] (no space after semicolon)
      const elementType = noirTypeToString({
        name: "",
        type: type.type,
        visibility: "public",
      });
      return `[${elementType};${type.length}]`;
    case "struct":
      // For structs, expand fields to match Aztec's FunctionSignatureDecoder
      // Aztec produces: (field1_type, field2_type, ...)
      if (type.fields && type.fields.length > 0) {
        const fieldTypes = type.fields
          .map((f: { name: string; type: AbiType }) =>
            noirTypeToString({
              name: f.name,
              type: f.type,
              visibility: "public",
            }),
          )
          .join(",");
        return `(${fieldTypes})`;
      }
      // Fallback for structs without fields
      return type.path.split("::").pop() || "Struct";
    default:
      return "Field"; // Default fallback
  }
}

/**
 * Build a function signature string from a function artifact.
 *
 * @param func - The function artifact from the contract
 * @returns Function signature string (e.g., "transfer_private(Field,Field,u128,Field)")
 */
export function buildFunctionSignature(func: FunctionArtifact): string {
  const params = func.parameters.map(noirTypeToString).join(",");
  return `${func.name}(${params})`;
}

// Cache for raw JSON artifacts - these contain all functions including unconstrained ones
const rawArtifactCache = new Map<string, any>();

/**
 * Register a raw JSON artifact for function signature lookup.
 * Call this when loading a contract to enable EIP-712 clear signing for all functions.
 *
 * @param contractName - Unique name for the contract
 * @param rawJson - The raw JSON artifact before loadContractArtifact processing
 */
export function registerRawArtifact(contractName: string, rawJson: any): void {
  rawArtifactCache.set(contractName, rawJson);
}

/**
 * Check if a function is a constrained (private) function.
 * Only constrained functions should have EIP-712 context set, because unconstrained
 * public functions are dispatched differently by the SDK.
 *
 * Note: We check the raw artifact cache because the processed artifact's function
 * objects don't have an is_unconstrained property (it's lost during loadContractArtifact).
 *
 * @param artifact - The contract artifact
 * @param methodName - The method name to check
 * @returns true if the function is constrained (private), false if unconstrained (public)
 */
export function isConstrainedFunction(
  artifact: ContractArtifact,
  methodName: string,
): boolean {
  // Check raw artifacts for the is_unconstrained property
  for (const rawArtifact of rawArtifactCache.values()) {
    if (rawArtifact?.functions) {
      const rawFunc = rawArtifact.functions.find(
        (f: any) => f.name === methodName,
      );
      if (rawFunc) {
        // is_unconstrained: true means it's a public/unconstrained function
        return rawFunc.is_unconstrained !== true;
      }
    }
  }

  // If not found in raw artifacts, check the processed artifact
  // and assume it's constrained if found
  const found = artifact.functions.find((f) => f.name === methodName);
  if (found) {
    return true;
  }

  // Function not found anywhere - assume not constrained to be safe
  return false;
}

/**
 * Find a function artifact by name from a contract artifact.
 *
 * Note: loadContractArtifact may filter out some functions (like unconstrained public functions).
 * We check both the processed artifact and raw JSON artifacts for the full function list.
 *
 * @param artifact - The contract artifact
 * @param methodName - The method name to find
 * @returns The function artifact or undefined
 */
export function findFunctionArtifact(
  artifact: ContractArtifact,
  methodName: string,
): FunctionArtifact | undefined {
  // First try the processed functions array
  const found = artifact.functions.find((f) => f.name === methodName);
  if (found) return found;

  // If not found, search all raw artifacts
  // This handles unconstrained public functions that are filtered out by loadContractArtifact
  for (const rawArtifact of rawArtifactCache.values()) {
    if (rawArtifact?.functions) {
      const rawFunc = rawArtifact.functions.find(
        (f: any) => f.name === methodName,
      );
      if (rawFunc && rawFunc.abi?.parameters) {
        // Convert raw function to FunctionArtifact format
        return {
          name: rawFunc.name,
          parameters: rawFunc.abi.parameters,
          returnTypes: rawFunc.abi.return_type ? [rawFunc.abi.return_type] : [],
          isInitializer:
            rawFunc.custom_attributes?.includes("abi_initializer") ?? false,
          isInternal:
            rawFunc.custom_attributes?.includes("abi_internal") ?? false,
          bytecode: rawFunc.bytecode,
          debugSymbols: rawFunc.debug_symbols,
          errorTypes: rawFunc.abi.error_types ?? {},
        } as unknown as FunctionArtifact;
      }
    }
  }

  return undefined;
}

/**
 * Convert various argument types to bigint for EIP-712 encoding.
 *
 * @param arg - The argument to convert
 * @returns The argument as bigint
 */
export function argToField(arg: unknown): bigint {
  if (typeof arg === "bigint") {
    return arg;
  }
  if (typeof arg === "number") {
    return BigInt(arg);
  }
  if (typeof arg === "boolean") {
    return arg ? 1n : 0n;
  }
  if (typeof arg === "string") {
    // Handle hex strings
    if (arg.startsWith("0x")) {
      return BigInt(arg);
    }
    // Try to parse as number
    return BigInt(arg);
  }
  // Handle Fr-like objects
  if (arg && typeof arg === "object" && "toBigInt" in arg) {
    return (arg as { toBigInt: () => bigint }).toBigInt();
  }
  // Handle AztecAddress-like objects
  if (arg && typeof arg === "object" && "toField" in arg) {
    const field = (
      arg as { toField: () => { toBigInt: () => bigint } }
    ).toField();
    return field.toBigInt();
  }

  throw new Error(`Cannot convert ${typeof arg} to field: ${String(arg)}`);
}

/**
 * Convert an array of arguments to bigint fields.
 *
 * @param args - The arguments to convert
 * @returns Array of bigint fields
 */
export function argsToFields(args: unknown[]): bigint[] {
  return args.map(argToField);
}

/**
 * Extended FunctionCallInput with optional selector for public functions
 */
export interface ExtendedFunctionCallInput extends FunctionCallInput {
  selector?: bigint;
}

/**
 * Build a FunctionCallInput from contract interaction parameters.
 *
 * @param targetAddress - The contract address
 * @param artifact - The contract artifact
 * @param methodName - The method name
 * @param args - The method arguments
 * @returns FunctionCallInput for EIP-712 context
 */
export async function buildFunctionCallInput(
  targetAddress: AztecAddress | bigint | string,
  artifact: ContractArtifact,
  methodName: string,
  args: unknown[],
): Promise<ExtendedFunctionCallInput> {
  // Find the function in the artifact
  const func = findFunctionArtifact(artifact, methodName);
  if (!func) {
    throw new Error(`Method ${methodName} not found in contract artifact`);
  }

  // Build the function signature
  const functionSignature = buildFunctionSignature(func);

  // Check if this is a public (unconstrained) function
  // For public functions, the args_hash in AppPayload includes the selector
  const isConstrained = isConstrainedFunction(artifact, methodName);
  const isPublic = !isConstrained;

  // Compute the function selector if it's a public function
  let selector: bigint | undefined;
  if (isPublic) {
    const funcSelector = await FunctionSelector.fromNameAndParameters(
      func.name,
      func.parameters,
    );
    selector = funcSelector.toField().toBigInt();
  }

  // Convert address to bigint
  // IMPORTANT: For AztecAddress, we must use toField().toBigInt() to get the
  // correct field representation that matches what AppPayload uses internally.
  let addressBigInt: bigint;
  if (typeof targetAddress === "bigint") {
    addressBigInt = targetAddress;
  } else if (typeof targetAddress === "string") {
    addressBigInt = BigInt(targetAddress);
  } else {
    // AztecAddress - must convert through toField() to match AppPayload encoding
    const aztecAddr = targetAddress as {
      toField: () => { toBigInt: () => bigint };
      toBigInt?: () => bigint;
    };
    if (aztecAddr.toField) {
      addressBigInt = aztecAddr.toField().toBigInt();
    } else if (aztecAddr.toBigInt) {
      addressBigInt = aztecAddr.toBigInt();
    } else {
      throw new Error(
        "Cannot convert address to bigint: no toField or toBigInt method",
      );
    }
  }

  // Convert arguments to fields
  const fieldArgs = argsToFields(args);

  return {
    targetAddress: addressBigInt,
    functionSignature,
    args: fieldArgs,
    isPublic,
    selector,
  };
}

/**
 * Build multiple FunctionCallInputs for a batched transaction.
 *
 * @param calls - Array of call parameters
 * @returns Array of FunctionCallInputs
 */
export async function buildFunctionCallInputs(
  calls: Array<{
    targetAddress: AztecAddress | bigint | string;
    artifact: ContractArtifact;
    methodName: string;
    args: unknown[];
  }>,
): Promise<ExtendedFunctionCallInput[]> {
  return Promise.all(
    calls.map((call) =>
      buildFunctionCallInput(
        call.targetAddress,
        call.artifact,
        call.methodName,
        call.args,
      ),
    ),
  );
}
