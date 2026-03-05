/**
 * Merkle Tree Generator for EIP-712 V2 Variable Argument Types (Approach 2)
 *
 * Generates Poseidon2 Merkle trees for whitelisting valid type_hash(FunctionCall{N}) values.
 *
 * Approach 2: leaves are keccak256(fc_encode_type) instead of keccak256(args_type_string).
 * - Arguments1 tree: fc_encode_type = FC1_PRIMARY + args_type_string
 * - Arguments2 tree: fc_encode_type = FC2_PRIMARY + args_type_string
 * - Arguments tree:  fc_encode_type = FC_AUTH_PRIMARY + args_type_string + AUTHWIT_APP_DOMAIN_DEF
 *
 * For each struct name (Arguments, Arguments1, Arguments2):
 * - Enumerates all valid (arg_count, type_combination) pairs for 0..10 args × 3 types
 * - Computes keccak256(fc_encode_type) for each combination
 * - Converts to BN254 Field (mod p, truncating 2 MSBs)
 * - Builds a balanced Poseidon2 Merkle tree
 * - Outputs: root, tree depth, and full tree data (leaves + sibling paths)
 *
 * Total leaves per tree: Σ(3^k, k=0..10) = 88,573. Padded to 2^17 = 131,072.
 *
 * Usage: npx tsx packages/contracts/scripts/generate-merkle-trees.ts
 */

import { keccak256, encodePacked } from "viem";
import { MerkleTreeCalculator } from "@aztec/foundation/trees";
import { Fr } from "@aztec/aztec.js/fields";

// =============================================================================
// Constants
// =============================================================================

const ARGUMENT_TYPES = ["bytes32", "uint256", "int256"] as const;
const MAX_ARGS = 10;
const TREE_DEPTH = 17;
const PADDED_SIZE = 1 << TREE_DEPTH; // 131072

/** BN254 scalar field modulus */
const BN254_FR_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

// FC primary strings (must match Noir constants in eip712_v2.nr)
const FC1_PRIMARY =
  "FunctionCall1(bytes32 contract,string functionSignature,Arguments1 arguments,bool isPublic,bool hideMsgSender,bool isStatic)";
const FC2_PRIMARY =
  "FunctionCall2(bytes32 contract,string functionSignature,Arguments2 arguments,bool isPublic,bool hideMsgSender,bool isStatic)";
const FC_AUTH_PRIMARY =
  "FunctionCallAuthorization(AuthwitAppDomain appDomain,bytes32 contract,string functionSignature,Arguments arguments,bool isPublic)";
const AUTHWIT_APP_DOMAIN_DEF =
  "AuthwitAppDomain(uint256 chainId,bytes32 verifyingContract)";

/**
 * Build the full FunctionCall encode_type for a given struct name and args type string.
 */
function buildFcEncodeType(structName: string, argsTypeString: string): string {
  switch (structName) {
    case "Arguments1":
      return FC1_PRIMARY + argsTypeString;
    case "Arguments2":
      return FC2_PRIMARY + argsTypeString;
    case "Arguments":
      return FC_AUTH_PRIMARY + argsTypeString + AUTHWIT_APP_DOMAIN_DEF;
    default:
      throw new Error(`Unknown struct name: ${structName}`);
  }
}

// =============================================================================
// Type string generation
// =============================================================================

/**
 * Build the Arguments type string for a given struct name and type combination.
 * E.g. "Arguments1(bytes32 argument1,uint256 argument2)"
 */
function buildTypeString(
  structName: string,
  types: (typeof ARGUMENT_TYPES)[number][],
): string {
  if (types.length === 0) {
    return `${structName}()`;
  }
  const fields = types
    .map((type, i) => `${type} argument${i + 1}`)
    .join(",");
  return `${structName}(${fields})`;
}

/**
 * Enumerate all valid type combinations for 0..maxArgs arguments × 3 types.
 * Returns an array of type strings for the given struct name.
 */
function enumerateAllTypeStrings(
  structName: string,
  maxArgs: number = MAX_ARGS,
): string[] {
  const results: string[] = [];

  for (let argCount = 0; argCount <= maxArgs; argCount++) {
    if (argCount === 0) {
      results.push(buildTypeString(structName, []));
      continue;
    }

    // Enumerate all combinations of 3 types for argCount positions
    const totalCombinations = 3 ** argCount;
    for (let combo = 0; combo < totalCombinations; combo++) {
      const types: (typeof ARGUMENT_TYPES)[number][] = [];
      let remaining = combo;
      for (let pos = 0; pos < argCount; pos++) {
        types.push(ARGUMENT_TYPES[remaining % 3]);
        remaining = Math.floor(remaining / 3);
      }
      results.push(buildTypeString(structName, types));
    }
  }

  return results;
}

/**
 * Compute keccak256 hash for a string.
 */
function computeStringHash(s: string): bigint {
  const hash = keccak256(encodePacked(["string"], [s]));
  return BigInt(hash);
}

/**
 * Convert a 256-bit keccak256 hash to a BN254 Field element.
 * Uses modular reduction (mod p). The 2 MSBs are effectively truncated
 * since p < 2^254, giving negligible collision risk.
 */
function hashToField(hash: bigint): Fr {
  return new Fr(hash % BN254_FR_MODULUS);
}

// =============================================================================
// Tree generation
// =============================================================================

interface TreeData {
  structName: string;
  root: Fr;
  depth: number;
  /** Map from type_hash (as hex) to {leafIndex, siblingPath} */
  proofs: Map<string, { leafIndex: number; siblingPath: Fr[] }>;
  /** All leaves as Fields (padded to power of 2) */
  leaves: Fr[];
  /** Map from type string to type_hash field value */
  typeStringToField: Map<string, Fr>;
}

/**
 * Generate a Merkle tree for a given struct name.
 */
async function generateTree(structName: string): Promise<TreeData> {
  console.log(`\nGenerating tree for ${structName}...`);

  // 1. Enumerate all args type strings
  const argsTypeStrings = enumerateAllTypeStrings(structName);
  console.log(`  Total type strings: ${argsTypeStrings.length}`);

  // 2. Compute fc_encode_type hashes and convert to Fields (Approach 2)
  const typeStringToField = new Map<string, Fr>();
  const leafFields: Fr[] = [];

  for (const argsTS of argsTypeStrings) {
    const fcEncodeType = buildFcEncodeType(structName, argsTS);
    const hash = computeStringHash(fcEncodeType);
    const field = hashToField(hash);
    typeStringToField.set(argsTS, field);
    leafFields.push(field);
  }

  // 3. Pad to power of 2
  const zeroLeaf = Fr.ZERO;
  while (leafFields.length < PADDED_SIZE) {
    leafFields.push(zeroLeaf);
  }
  console.log(`  Padded to ${leafFields.length} leaves (depth ${TREE_DEPTH})`);

  // 4. Build Merkle tree using Poseidon2
  const leafBuffers = leafFields.map((f) => f.toBuffer());
  const calculator = await MerkleTreeCalculator.create(TREE_DEPTH);
  const tree = await calculator.computeTree(leafBuffers);

  const root = Fr.fromBuffer(tree.root);
  console.log(`  Root: ${root.toString()}`);

  // 5. Build proof map
  const proofs = new Map<string, { leafIndex: number; siblingPath: Fr[] }>();
  for (const [ts, field] of typeStringToField.entries()) {
    const leafIndex = tree.getIndex(field.toBuffer());
    const siblingPath = tree
      .getSiblingPath(leafIndex)
      .map((b: Buffer) => Fr.fromBuffer(b));
    const hexKey = field.toString();
    proofs.set(hexKey, { leafIndex, siblingPath });
  }

  return {
    structName,
    root,
    depth: TREE_DEPTH,
    proofs,
    leaves: leafFields,
    typeStringToField,
  };
}

// =============================================================================
// Output formatting
// =============================================================================

function frToNoirBytes(fr: Fr): string {
  const hex = fr.toString().slice(2); // remove 0x
  const padded = hex.padStart(64, "0");
  const bytes: string[] = [];
  for (let i = 0; i < 64; i += 2) {
    bytes.push(`0x${padded.slice(i, i + 2)}`);
  }
  return bytes.join(", ");
}

function formatNoirRoot(name: string, fr: Fr): string {
  return `pub global ${name}: Field = ${fr.toString()};`;
}

/**
 * Output Noir constants for all 3 trees.
 */
function outputNoirConstants(trees: TreeData[]): void {
  console.log("\n// =============================================================================");
  console.log("// Noir Constants (paste into eip712_v2.nr)");
  console.log("// =============================================================================\n");

  console.log(`pub global MERKLE_DEPTH: u32 = ${TREE_DEPTH};\n`);

  for (const tree of trees) {
    const nameMap: Record<string, string> = {
      Arguments: "MERKLE_ROOT_ARGS",
      Arguments1: "MERKLE_ROOT_ARGS1",
      Arguments2: "MERKLE_ROOT_ARGS2",
    };
    const name = nameMap[tree.structName] || `MERKLE_ROOT_${tree.structName.toUpperCase()}`;
    console.log(formatNoirRoot(name, tree.root));
  }
}

/**
 * Output TypeScript tree data module.
 */
function outputTypeScriptData(trees: TreeData[]): void {
  console.log("\n// =============================================================================");
  console.log("// TypeScript Data (for merkle-tree-data.ts)");
  console.log("// =============================================================================\n");

  console.log("// Merkle roots");
  for (const tree of trees) {
    console.log(`export const MERKLE_ROOT_${tree.structName.toUpperCase()} = "${tree.root.toString()}" as const;`);
  }
  console.log(`\nexport const MERKLE_DEPTH = ${TREE_DEPTH};`);
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  console.log("EIP-712 V2 Merkle Tree Generator");
  console.log("================================");
  console.log(`Max args: ${MAX_ARGS}`);
  console.log(`Tree depth: ${TREE_DEPTH}`);
  console.log(`Padded size: ${PADDED_SIZE}`);

  // Compute total leaves
  let totalLeaves = 0;
  for (let k = 0; k <= MAX_ARGS; k++) {
    totalLeaves += 3 ** k;
  }
  console.log(`Total unique leaves per tree: ${totalLeaves}`);

  // Generate trees
  const trees = await Promise.all([
    generateTree("Arguments"),
    generateTree("Arguments1"),
    generateTree("Arguments2"),
  ]);

  // Output constants
  outputNoirConstants(trees);
  outputTypeScriptData(trees);

  // Write JSON data for TS consumption
  const jsonOutput: Record<
    string,
    {
      root: string;
      depth: number;
      proofs: Record<string, { leafIndex: number; siblingPath: string[] }>;
      typeStringMap: Record<string, string>;
    }
  > = {};

  for (const tree of trees) {
    const proofs: Record<string, { leafIndex: number; siblingPath: string[] }> =
      {};
    for (const [key, proof] of tree.proofs.entries()) {
      proofs[key] = {
        leafIndex: proof.leafIndex,
        siblingPath: proof.siblingPath.map((f) => f.toString()),
      };
    }

    const typeStringMap: Record<string, string> = {};
    for (const [ts, field] of tree.typeStringToField.entries()) {
      typeStringMap[ts] = field.toString();
    }

    jsonOutput[tree.structName] = {
      root: tree.root.toString(),
      depth: tree.depth,
      proofs,
      typeStringMap,
    };
  }

  // Write to file
  const fs = await import("fs");
  const path = await import("path");
  const outPath = path.resolve(
    import.meta.dirname,
    "../../eip712/src/lib/merkle-tree-data.generated.json",
  );
  fs.writeFileSync(outPath, JSON.stringify(jsonOutput, null, 2));
  console.log(`\nTree data written to: ${outPath}`);
}

main().catch(console.error);
