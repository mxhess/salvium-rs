                                                                                                                                                                                                          
import { Wallet } from '../src/wallet.js';
import { setCryptoBackend } from '../src/crypto/index.js';                                                                                                                                                                   
await setCryptoBackend('wasm');                                                                                                                                                                                             
                                                                                                                                                                                                                            
const w = Wallet.create({ network: 'mainnet' });                                                                                                                                                                            
                                                                                                                                                                                                                            
console.log('salvium-js v0.5.0');                                                                                                                                                                                           
console.log('─'.repeat(50));                                                                                                                                                                                                
console.log();                                                                                                                                                                                                              
console.log('Wallet Security:');                                                                                                                                                                                            
console.log('  Encryption at rest:  ML-KEM-768 (CRYSTALS-Kyber)');                                                                                                                                                          
console.log('  Key derivation:      Argon2id (64 MB, 3 iterations)');                                                                                                                                                       
console.log('  Symmetric cipher:    AES-256-GCM');                                                                                                                                                                          
console.log('  Hybrid scheme:       PQ-KEM + classical KDF');                                                                                                                                                               
console.log();                                                                                                                                                                                                              
console.log('Protocol Support:');                                                                                                                                                                                           
console.log('  Address formats:     CryptoNote (SaLv) + CARROT (SC1)');                                                                                                                                                     
console.log('  Transaction types:   Transfer, Sweep, Stake, Burn, Convert');                                                                                                                                                
console.log('  Ring signatures:     TCLSAG (16-member rings)');                                                                                                                                                             
console.log('  Range proofs:        Bulletproofs+');                                                                                                                                                                        
console.log('  Amount hiding:       Pedersen commitments');                                                                                                                                                                 
console.log();                                                                                                                                                                                                              
                                                                                                                                                                                                                            
// Time the encrypt/decrypt                                                                                                                                                                                                 
const start = performance.now();                                                                                                                                                                                            
const enc = w.toEncryptedJSON('benchmark');
const mid = performance.now();
Wallet.fromEncryptedJSON(enc, 'benchmark');
const end = performance.now();

console.log('Performance:');
console.log('  PQ encrypt wallet:   ' + (mid - start).toFixed(0) + ' ms');
console.log('  PQ decrypt wallet:   ' + (end - mid).toFixed(0) + ' ms');
console.log('  Kyber ciphertext:    ' + (enc.encryption.kyberCiphertext.length / 2) + ' bytes');
console.log();
console.log('Your keys are quantum-safe. Are yours?');

