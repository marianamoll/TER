 // on "charge" le code des pour pouvoir implementer ses méthodes
use::des::Des; 
use cipher::{BlockEncrypt,KeyInit};
use cipher::generic_array::GenericArray;

pub fn f_des(key:u64,state:u64)->u64{
    let keys=key.to_be_bytes();
    let states=state.to_be_bytes(); //on transforme en 8bits 
    let cipher=Des::new(&keys.into());
    let mut block=GenericArray::clone_from_slice(&states);
    cipher.encrypt_block(&mut block);
    let sol=u64::from_be_bytes(block.into());
    sol
}
