/**
 * Merkle Tree Generator for EIP-712 V2 Variable Argument Types (Approach 2)
 *
 * Generates Poseidon2 Merkle trees for whitelisting valid type_hash(FunctionCall) values.
 *
 * Approach 2: leaves are keccak256(fc_encode_type) instead of keccak256(args_type_string).
 * - FunctionCall tree: fc_encode_type = FC_PRIMARY + args_type_string
 * - Arguments tree:    fc_encode_type = FC_AUTH_PRIMARY + args_type_string + AUTHWIT_APP_DOMAIN_DEF
 *
 * For each tree (FunctionCall, Arguments):
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
const MAX_ARGS_IN_JSON = 5; // Only include proofs for argCount 0..5 in the JSON (~0.9MB vs ~299MB)
const TREE_DEPTH = 17;
const PADDED_SIZE = 1 << TREE_DEPTH; // 131072

/** BN254 scalar field modulus */
const BN254_FR_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

// FC primary strings (must match Noir constants in eip712_v2.nr)
const FC_PRIMARY =
  "FunctionCall(bytes32 contract,string functionSignature,Arguments arguments,bool isPublic,bool hideMsgSender,bool isStatic)";
const FC_AUTH_PRIMARY =
  "FunctionCallAuthorization(AuthwitAppDomain appDomain,bytes32 contract,string functionSignature,Arguments arguments,bool isPublic)";
const AUTHWIT_APP_DOMAIN_DEF =
  "AuthwitAppDomain(uint256 chainId,bytes32 verifyingContract)";

/**
 * Build the full FunctionCall encode_type for a given tree name and args type string.
 */
function buildFcEncodeType(structName: string, argsTypeString: string): string {
  switch (structName) {
    case "FunctionCall":
      return FC_PRIMARY + argsTypeString;
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
 * Build the Arguments type string for a given type combination.
 * Always uses "Arguments" as the struct name.
 * E.g. "Arguments(bytes32 argument1,uint256 argument2)"
 */
function buildTypeString(
  types: (typeof ARGUMENT_TYPES)[number][],
): string {
  if (types.length === 0) {
    return "Arguments()";
  }
  const fields = types
    .map((type, i) => `${type} argument${i + 1}`)
    .join(",");
  return `Arguments(${fields})`;
}

/**
 * Enumerate all valid type combinations for 0..maxArgs arguments × 3 types.
 * Always uses "Arguments" as the struct name.
 * Returns both the type string and the argCount for each entry.
 */
function enumerateAllTypeStrings(
  maxArgs: number = MAX_ARGS,
): { typeString: string; argCount: number }[] {
  const results: { typeString: string; argCount: number }[] = [];

  for (let argCount = 0; argCount <= maxArgs; argCount++) {
    if (argCount === 0) {
      results.push({ typeString: buildTypeString([]), argCount: 0 });
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
      results.push({ typeString: buildTypeString(types), argCount });
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
  /** Map from type_hash (as hex) to {leafIndex, siblingPath, argCount} */
  proofs: Map<string, { leafIndex: number; siblingPath: Fr[]; argCount: number }>;
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

  // 1. Enumerate all args type strings (always "Arguments")
  const argsTypeEntries = enumerateAllTypeStrings();
  console.log(`  Total type strings: ${argsTypeEntries.length}`);

  // 2. Compute fc_encode_type hashes and convert to Fields (Approach 2)
  const typeStringToField = new Map<string, Fr>();
  const leafArgCounts = new Map<string, number>(); // hex key → argCount
  const leafFields: Fr[] = [];

  for (const { typeString: argsTS, argCount } of argsTypeEntries) {
    const fcEncodeType = buildFcEncodeType(structName, argsTS);
    const hash = computeStringHash(fcEncodeType);
    const field = hashToField(hash);
    typeStringToField.set(argsTS, field);
    leafArgCounts.set(field.toString(), argCount);
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
  const proofs = new Map<string, { leafIndex: number; siblingPath: Fr[]; argCount: number }>();
  for (const [ts, field] of typeStringToField.entries()) {
    const leafIndex = tree.getIndex(field.toBuffer());
    const siblingPath = tree
      .getSiblingPath(leafIndex)
      .map((b: Buffer) => Fr.fromBuffer(b));
    const hexKey = field.toString();
    const argCount = leafArgCounts.get(hexKey) ?? 0;
    proofs.set(hexKey, { leafIndex, siblingPath, argCount });
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
 * Output Noir constants for both trees.
 */
function outputNoirConstants(trees: TreeData[]): void {
  console.log("\n// =============================================================================");
  console.log("// Noir Constants (paste into eip712_v2.nr)");
  console.log("// =============================================================================\n");

  console.log(`pub global MERKLE_DEPTH: u32 = ${TREE_DEPTH};\n`);

  for (const tree of trees) {
    const nameMap: Record<string, string> = {
      FunctionCall: "MERKLE_ROOT_FC",
      Arguments: "MERKLE_ROOT_FC_AUTH",
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
    const nameMap: Record<string, string> = {
      FunctionCall: "MERKLE_ROOT_FC",
      Arguments: "MERKLE_ROOT_FC_AUTH",
    };
    const name = nameMap[tree.structName] || `MERKLE_ROOT_${tree.structName.toUpperCase()}`;
    console.log(`export const ${name} = "${tree.root.toString()}" as const;`);
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
    generateTree("FunctionCall"),
    generateTree("Arguments"),
  ]);

  // Output constants
  outputNoirConstants(trees);
  outputTypeScriptData(trees);

  // Write JSON data for TS consumption (only proofs for argCount 0..MAX_ARGS_IN_JSON)
  const jsonOutput: Record<string, unknown> = {
    maxArgsInJson: MAX_ARGS_IN_JSON,
  };

  for (const tree of trees) {
    const proofs: Record<string, { leafIndex: number; siblingPath: string[] }> =
      {};
    let includedCount = 0;
    let skippedCount = 0;
    for (const [key, proof] of tree.proofs.entries()) {
      if (proof.argCount > MAX_ARGS_IN_JSON) {
        skippedCount++;
        continue;
      }
      proofs[key] = {
        leafIndex: proof.leafIndex,
        siblingPath: proof.siblingPath.map((f) => f.toString()),
      };
      includedCount++;
    }

    jsonOutput[tree.structName] = {
      root: tree.root.toString(),
      depth: tree.depth,
      proofs,
    };

    console.log(`  ${tree.structName}: ${includedCount} proofs included, ${skippedCount} skipped (argCount > ${MAX_ARGS_IN_JSON})`);
  }

  // Write to file
  const fs = await import("fs");
  const path = await import("path");
  const outPath = path.resolve(
    import.meta.dirname,
    "../../eip712/src/lib/merkle-tree-data.generated.json",
  );
  fs.writeFileSync(outPath, JSON.stringify(jsonOutput, null, 2));

  const sizeBytes = fs.statSync(outPath).size;
  const sizeMB = (sizeBytes / (1024 * 1024)).toFixed(2);
  console.log(`\nTree data written to: ${outPath} (${sizeMB} MB)`);
}

main().catch(console.error);
