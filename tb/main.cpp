#include "../src/sha256.h"

#include <cstring>
#include <iostream>

#define TB_SIZE 4

int main(int argc, char *argv[]){

	char msg[TB_SIZE][CTX_MEM_SIZE] = {
		"asldkfja;woeijafw opeiajwpe ofawpeawoefkjawpe ofaiw jefaop;weijfpa oweijfawoeifaj woeifajwe pofaijwepoafiwje foawiejf aopwiejpf aowiejpfoaw ijeaopwiejf aoweijf paowiejfapowe jao",
		"111111111111111110-2j1v m-230r1j23-10j1r04j9019 2q04 q290  109wfe801f a89r10ag98eth04d9ry40 jf8j409 u61bkb03hi510 l65i13ljo3i5;0801fv3yu854k0 /f964870 k6xde48465 06su84r0 3h5ts40 3.x4t84h 0s3.er8t4hs80er4gx9h/t7 09yhx3rt540 hx3.t84hx.03r5t h40x.3tx840 84x3t.40 xh3.1x3ft8504 h3x84.3 5th4 8",
		"asdfjkl",
		"asdfjklasdfjklasdfjklasdfjklasdfjklasdfjklasdfjklasdfjkl"
	};

	u256_t answer[] = {
		u256_t("b699f9201bd11569d594a88403f144ce00e500897fc8097a2719ccc78f4fc299", 16),
		u256_t("3474ec2fb93a6c928b196208fa8c9352a732fef41d10261853ce6d72855e808c", 16),
		u256_t("f7d5d2aa07500f016664a006944078dbbf086c136b4bedb8d033bd8c82da212f", 16),
		u256_t("a3976c5e1ad879d4b8af1c48d1be8355debe574ceaf4fa5b78a62f2c8b1c754a", 16)
	};


	bool pass = true;
	for (int i=0; i<TB_SIZE; i++){
		u256_t result = sha256(msg[i], (u64_t)strlen(msg[i]));
		std::cout << std::hex << result << std::endl;
		pass &= (result==answer[i]);
	}

	if (!pass){
		std::cout << "Test Fail!" << std::endl;
		return 1;
	} else{
		std::cout << "Test Pass!" << std::endl;
		return 0;
	}

}
