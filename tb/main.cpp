#include "../src/sha256.h"

#include <cstring>
#include <iostream>

int main(int argc, char *argv[]){
#if 1
	char msg[] = "asldkfja;woeijafw opeiajwpe ofawpeawoefkjawpe ofaiw jefaop;weijfpa oweijfawoeifaj woeifajwe pofaijwepoafiwje foawiejf aopwiejpf aowiejpfoaw ijeaopwiejf aoweijf paowiejfapowe jao";
	u256_t answer("b699f9201bd11569d594a88403f144ce00e500897fc8097a2719ccc78f4fc299", 16);
#else
	char msg[] = "111111111111111110-2j1v m-230r1j23-10j1r04j9019 2q04 q290  109wfe801f a89r10ag98eth04d9ry40 jf8j409 u61bkb03hi510 l65i13ljo3i5;0801fv3yu854k0 /f964870 k6xde48465 06su84r0 3h5ts40 3.x4t84h 0s3.er8t4hs80er4gx9h/t7 09yhx3rt540 hx3.t84hx.03r5t h40x.3tx840 84x3t.40 xh3.1x3ft8504 h3x84.3 5th4 8";
	u256_t answer("3474ec2fb93a6c928b196208fa8c9352a732fef41d10261853ce6d72855e808c", 16);
#endif
	u256_t result = sha256(msg, (u64_t)strlen(msg));

	std::cout << std::hex << result << std::endl;

	if (result != answer){
		std::cout << "Test Fail!" << std::endl;
		return 1;
	}

	else{
		std::cout << "Test Pass!" << std::endl;
		return 0;
	}
}
