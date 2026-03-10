//je vais faire une fonction itérative pour des messages de 128 bits 
mod des; 
use des::f_des;
use cipher::generic_array::GenericArray;
const masque_24: u32 = 0xFFFFFF;
const masque_48: u64 = 0xFFFFFFFFFFFF; // comme on a pas 24 bits on utilise ceci qui ne garde que les 24 premiers
fn f_feist(x:u32, k:u32)->u32{// petite fonction feistel qu'on doit faire 4 fois
    let y =(x^k) &masque_24;
    ((y<<7)|(y>>(24-7)))& masque_24 //la rotation
}
fn feistel(mes:u64, keys: [u32;4])->u64{
    let mut r= ((mes >>24)as u32) & masque_24;
    let mut l =(mes as u32)&masque_24;
    for i in 0..4{
        let temp=r; 
        r=(l^f_feist(r,keys[i]))&masque_24;
        l=temp; 
    }
    (l as u64)|(r as u64)<< 24
}
fn pad_1(clair:u32)->u128{
    let msg=clair;
    let mut pad=(msg as u128)<<128-32;
    pad|=1<<(128-33);
    pad
}
fn pad_2(clair:u64)->u128{
    let msg=clair&masque_48;
    let mut pad = (msg as u128) << (128 - 48);
    pad |=1 << (128 - 49);
    pad
}
fn split_32(block:u128)->[u32;4]{
    [
        ((block >> 104) as u32) & 0xFFFFFF,
        ((block >> 80) as u32) & 0xFFFFFF,
        ((block >> 56) as u32) & 0xFFFFFF,
        ((block >> 32) as u32) & 0xFFFFFF,
    ]

}
fn split_64(block:u128)->[u64;2]{
    let high = (block >> 64) as u64;
    let low = block as u64;
    [high,low]

}
fn f_iterative_1(iv: u64, mes: u64) -> u64 {
    let padded = pad_2(mes);
    let subkeys = split_32(padded); // [u32;4]
    let mut state = iv & masque_48;

    for &k in &subkeys {
        // on crée 4 sous-clés identiques pour le Feistel
        let round_keys = split_32(pad_1(k));

        let encrypted = feistel(state, round_keys);

        state = (encrypted ^ state) & masque_48;
    }

    state
}
fn f_iterative_2(iv:u64,mes:u64)->u64{
    //j'ai besoin de créer 4 blocs de u64 
    let padded=pad_2(mes);
    let subkeys=split_64(padded);
    let mut state=iv; 
    for &k in &subkeys{

        let encripted=f_des(k,state);
        state=encripted^state;
    }
    state
}
fn main() {
    let iv  = 0x123456789ABC;
    let mes = 0xABCDEF123456;
    let h_1=f_iterative_1(iv,mes);
    println!("Hash 1 fonction facile= {:012X}", h_1);
    let h_2=f_iterative_2(iv,mes);
    println!("Hash fonction de compression DES={:012X}",h_2)
}
