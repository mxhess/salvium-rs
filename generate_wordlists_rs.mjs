import { readFileSync, writeFileSync } from 'fs';

const langs = [
  { file: "english", varName: "ENGLISH" },
  { file: "spanish", varName: "SPANISH" },
  { file: "french", varName: "FRENCH" },
  { file: "german", varName: "GERMAN" },
  { file: "italian", varName: "ITALIAN" },
  { file: "portuguese", varName: "PORTUGUESE" },
  { file: "dutch", varName: "DUTCH" },
  { file: "russian", varName: "RUSSIAN" },
  { file: "japanese", varName: "JAPANESE" },
  { file: "chinese_simplified", varName: "CHINESE_SIMPLIFIED" },
  { file: "esperanto", varName: "ESPERANTO" },
  { file: "lojban", varName: "LOJBAN" },
];

for (const lang of langs) {
  const content = readFileSync("src/wordlists/" + lang.file + ".js", "utf8");
  const nameMatch = content.match(/export const name = '([^']*)'/);
  lang.displayName = nameMatch[1];
  const engMatch = content.match(/export const englishName = '([^']*)'/);
  lang.englishName = engMatch[1];
  const prefixMatch = content.match(/export const prefixLength = (\d+)/);
  lang.prefixLength = parseInt(prefixMatch[1]);
  const wordsMatch = content.match(/export const words = \[([\s\S]*?)\]/);
  const rawWords = wordsMatch[1];
  const words = [];
  const re = /"([^"]*)"/g;
  let m;
  while ((m = re.exec(rawWords)) !== null) {
    words.push(m[1]);
  }
  lang.words = words;
  if (words.length !== 1626) {
    console.error(`ERROR: ${lang.file} has ${words.length} words, expected 1626`);
    process.exit(1);
  }
}

let out = "";
out += "//! Mnemonic word lists for 12 languages.\n";
out += "//! Each list has exactly 1626 words, matching the CryptoNote/Salvium mnemonic scheme.\n";
out += "\n";
out += "pub struct WordList {\n";
out += "    pub name: &'static str,\n";
out += "    pub english_name: &'static str,\n";
out += "    pub prefix_length: usize,\n";
out += "    pub words: &'static [&'static str; 1626],\n";
out += "}\n\n";

out += "pub static ALL_LANGUAGES: [&WordList; 12] = [\n";
for (const lang of langs) {
  out += "    &" + lang.varName + ",\n";
}
out += "];\n\n";

for (const lang of langs) {
  out += "pub static " + lang.varName + ": WordList = WordList {\n";
  out += "    name: \"" + lang.displayName + "\",\n";
  out += "    english_name: \"" + lang.englishName + "\",\n";
  out += "    prefix_length: " + lang.prefixLength + ",\n";
  out += "    words: &" + lang.varName + "_WORDS,\n";
  out += "};\n\n";

  out += "static " + lang.varName + "_WORDS: [&str; 1626] = [\n";
  for (let i = 0; i < lang.words.length; i += 8) {
    const chunk = lang.words.slice(i, i + 8);
    // Escape backslashes and double quotes in words
    const escaped = chunk.map(w => '"' + w.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"');
    out += "    " + escaped.join(", ") + ",\n";
  }
  out += "];\n\n";
}

writeFileSync("crates/salvium-types/src/wordlists.rs", out);
console.log("Done! Wrote crates/salvium-types/src/wordlists.rs");
for (const lang of langs) {
  console.log(`  ${lang.file}: ${lang.words.length} words, prefix=${lang.prefixLength}, name="${lang.displayName}"`);
}
