const { HDNodeWallet } = require("ethers");

// Hardhat's default mnemonic is public and only suitable for a local demo chain.
const phrase = "test test test test test test test test test test test junk";
const root = HDNodeWallet.fromPhrase(phrase, undefined, "m/44'/60'/0'/0");
const roles = ["Registrar / initial admin", "Land office", "Survey office", "Identity issuer", "Welfare operator"];
console.log("LOCAL DEMO ONLY — never import these accounts on a public network.\n");
for (let index = 0; index < roles.length; index += 1) {
  const wallet = root.deriveChild(index);
  console.log(`${index + 1}. ${roles[index]}\n   Address: ${wallet.address}\n   Private key: ${wallet.privateKey}\n`);
}
