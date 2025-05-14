import {
	"gonum"
	"crypto/rand"
}

const n, q := 256, 3329
int k, n1, n2, du, dv = 2, 3, 2, 10, 4

type mlKem struct {
}




func (m *mlKem) KeyGen() (ek [384*k+32]byte, dk [768*k+96]byte) {
	//Generates an encapsulation key and a corresponding decapsulation key.
}

func (m *mlKem) Encaps(ek [384*k+32]byte) ([32]byte, [du*k+dv]byte){
	//Use the encapsulation key to generate a shared secret key and an associated ciphertext.
}

func (m *mlKem) Decaps(dk [768*k+96]byte, c [du*k+dv]byte){

}
