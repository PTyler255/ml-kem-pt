import (
	"log"
	"gonum"
	"crypto/rand"
)

const n, q := 256, 3329
int k, n1, n2, du, dv = 2, 3, 2, 10, 4

type mlKem struct {
}

type kPKE struct {}

func (m *mlKem) KeyGen() ([384*k+32]byte, [768*k+96]byte) {
	//Generates an encapsulation key and a corresponding decapsulation key. 
	d := make([]byte, 32)
	z := make([]byte, 32)
	rand.Read(d)
	rand.Read(z)
	//"[Read] never returns an error, and always fills the slice entirely" ~ crypto/rand documentation
	ek, dk := mlKem.keyGen_internal(d,z)
	return ek, dk
}

func (m *mlKem) keyGen_internal(d [32]byte, z [32]byte) ([384*k+32]byte, [768*k+96]byte) {
	ekp, dkp := kPKE.keyGen(d)
	ek = ekp
	dk = append(dkp, ek, H(ek), z)
	return ek, dk
}

func (m *mlKem) Encaps(ek [384*k+32]byte) ([32]byte, [du*k+dv]byte){
	//Use the encapsulation key to generate a shared secret key and an associated ciphertext.
	m := make([]byte, 32)
	rand.Read(m)
	K, c := mlKem.encaps_internal(ek, m)
	return K, c
}

func (m *mlKem) encaps_internal(ek [384*k+32]byte, m [32]byte) ([32]byte, [32*(du*k+dv)]byte) {
	//Use the encapsulation key to generate a shared secret key and an associated ciphertext.
	K, r := G(append(m, H(ek)...))
	c := kPKE.encrypt(ek,m,r)
	return K, c
}

func (m *mlKem) Decaps(dk [768*k+96]byte, c [du*k+dv]byte){
	//Uses the decapsulation key to produce a shared secret key from a ciphertext
	Kp := mlKem.decaps_internal(dk,c)
	return K
}

func (m *mlKem) decaps_internal(dk [768*k+96]byte, c [32*(du*k+dv)]byte) [32]byte {
	//Uses the decapsulation key to produce a shared secret key from a ciphertext
	dkp, ekp := dk[:384*k], dk[384*k:768*k+32]
	h, z := dk[768*k+32:768*k+64], dk[768*k+64:768*k+96]
	mp := kPKE.decrypt(dkp, c)
	Kp, rp := G(append(mp, h))
	K := J(append(z, c))
	cp := kPKE.encrypt(ekp, mp, rp)
	if c != cp {
		Kp = K
	}
	return Kp
}


//TODO: kPKE helper functions
func (k *kPKE) genKey () {}
func (k *kPKE) encrypt () {}
func (k *kPKE) decrypt () {}


//TODO: Hashing helper functions
func H() {}
func G() {}
func J() {}
