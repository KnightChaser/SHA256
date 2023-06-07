// C++ 20 Standard

#include <iostream>
#include <vector>
#include <string>
#include <assert.h>
#include <bitset>
#include <cmath>
#include <array>
using namespace std;

template <typename Tx>
ostream& operator<< (ostream& os, vector<Tx> inputVector) {

	for (Tx element : inputVector)
		os << element << " ";

	return os;

}

class SHA256 {
private:
public:
	uint32_t            rightRotate(uint32_t _x, uint32_t n);

	vector<uint8_t>     messagePreProcess(const string messageInput);
	vector<uint32_t>    makeInitializeHashValues();                             // H[x] (Size: 8)
	vector<uint32_t>    makeInitializeRoundConstants();                         // K[x] (Size: 64)

	uint32_t            changeEndian(uint32_t x);
	uint64_t            changeEndian(uint64_t x);
	uint32_t            sigma0(uint32_t _x);
	uint32_t            sigma1(uint32_t _x);
	uint32_t            bigSigma0(uint32_t _x);
	uint32_t            bigSigma1(uint32_t _x);
	uint32_t            choose(uint32_t _x, uint32_t _y, uint32_t _z);
	uint32_t            majority(uint32_t _x, uint32_t _y, uint32_t _z);
};

uint32_t SHA256::changeEndian(uint32_t x) {
	x = ((x << 8) & 0xFF00FF00) | ((x >> 8) & 0xFF00FF);
	return (x << 16) | (x >> 16);
}

uint64_t SHA256::changeEndian(uint64_t x) {
	x = ((x << 8) & 0xFF00FF00FF00FF00ULL) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
	x = ((x << 16) & 0xFFFF0000FFFF0000ULL) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
	return (x << 32) | (x >> 32);
}

vector<uint8_t> SHA256::messagePreProcess(const string messageInput) {

	vector<uint8_t> message(messageInput.begin(), messageInput.end());

	auto messageLength = static_cast<uint64_t>(message.size());

	// Append single 1s and seven 0s right after the end of the given message
	message.push_back(0b10000000);

	int zeroPaddingCount = 64 - (((messageLength % 64) + 9) % 64);
	if (zeroPaddingCount == 64)
		zeroPaddingCount = 0;

	for (int _ = 0; _ < zeroPaddingCount; ++_)
		message.push_back(0b00000000);

	// Append the bit length of original message, at the last part of the transformed message vector
	assert(messageLength <= UINT64_MAX / 8);    // must be true (not overflowing)
	uint64_t bitLengthInBigEndian = SHA256::changeEndian(messageLength * 8);      // byte to bit
	auto bitLengthDataPtr = reinterpret_cast<uint8_t *>(&bitLengthInBigEndian);

	message.insert(end(message), bitLengthDataPtr, bitLengthDataPtr + 8);       // put the length data
	assert(message.size() % 64 == 0);                                           // verify

	return message;

}

vector<uint32_t> SHA256::makeInitializeHashValues() {

	// h0 = 0x6a09e667
	// h1 = 0xbb67ae85
	// h2 = 0x3c6ef372
	// h3 = 0xa54ff53a
	// h4 = 0x510e527f
	// h5 = 0x9b05688c
	// h6 = 0x1f83d9ab
	// h7 = 0x5be0cd19

	// To calculate those Initialize Hash Values,
	// get the square root values of smallest 8 prime numbers(2, 3, 5, 7, 11, 13, 17, 19),
	// then extract the following 32 bits since the decimal point(.)
	const int primesForSHA256Hx[] = { 2, 3, 5, 7, 11, 13, 17, 19 };
	static_assert(sizeof(primesForSHA256Hx) / sizeof(*primesForSHA256Hx) == 8, "");     // Should be assured

	vector<uint32_t> HValues;

	for (int _seq = 0; _seq < 8; ++_seq) {
		double Hx = sqrt(primesForSHA256Hx[_seq]);

		Hx -= static_cast<uint32_t>(Hx);    // remove numbers >= 1
		Hx *= pow(16, 8);                   // extract 32 bit since the decimal point

		HValues.push_back(static_cast<uint32_t>(Hx));
	}

	return HValues;
}

vector<uint32_t> SHA256::makeInitializeRoundConstants() {

	// 0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5 0x3956c25b 0x59f111f1 0x923f82a4 0xab1c5ed5
	// 0xd807aa98 0x12835b01 0x243185be 0x550c7dc3 0x72be5d74 0x80deb1fe 0x9bdc06a7 0xc19bf174
	// 0xe49b69c1 0xefbe4786 0x0fc19dc6 0x240ca1cc 0x2de92c6f 0x4a7484aa 0x5cb0a9dc 0x76f988da
	// 0x983e5152 0xa831c66d 0xb00327c8 0xbf597fc7 0xc6e00bf3 0xd5a79147 0x06ca6351 0x14292967
	// 0x27b70a85 0x2e1b2138 0x4d2c6dfc 0x53380d13 0x650a7354 0x766a0abb 0x81c2c92e 0x92722c85
	// 0xa2bfe8a1 0xa81a664b 0xc24b8b70 0xc76c51a3 0xd192e819 0xd6990624 0xf40e3585 0x106aa070
	// 0x19a4c116 0x1e376c08 0x2748774c 0x34b0bcb5 0x391c0cb3 0x4ed8aa4a 0x5b9cca4f 0x682e6ff3
	// 0x748f82ee 0x78a5636f 0x84c87814 0x8cc70208 0x90befffa 0xa4506ceb 0xbef9a3f7 0xc67178f2

	const int primesForSHA256Kx[] = {
		2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
		31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
		73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
		127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
		179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
		233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
		283, 293, 307, 311
	};
	static_assert(sizeof(primesForSHA256Kx) / sizeof(*primesForSHA256Kx) == 64, "");    // Should be assured

	vector<uint32_t> KValues;

	for (int _seq = 0; _seq < 64; ++_seq) {

		double Kx = cbrt(primesForSHA256Kx[_seq]);

		Kx -= static_cast<uint32_t>(Kx);      // remove numbers >= 1
		Kx *= pow(16, 8);                     // extract 32 bit since the decimal point

		KValues.push_back(static_cast<uint32_t>(Kx));

	}

	return KValues;

}

uint32_t SHA256::rightRotate(uint32_t _x, uint32_t n) {
	return (_x >> n) | (_x << (32 - n));
}

uint32_t SHA256::sigma0(uint32_t _x) {
	uint32_t result = SHA256::rightRotate(_x, 7) ^ SHA256::rightRotate(_x, 18) ^ (_x >> 3);
	return result;
}

uint32_t SHA256::sigma1(uint32_t _x) {
	uint32_t result = SHA256::rightRotate(_x, 17) ^ SHA256::rightRotate(_x, 19) ^ (_x >> 10);
	return result;
}

uint32_t SHA256::bigSigma0(uint32_t _x) {
	uint32_t result = SHA256::rightRotate(_x, 2) ^ SHA256::rightRotate(_x, 13) ^ SHA256::rightRotate(_x, 22);
	return result;
}

uint32_t SHA256::bigSigma1(uint32_t _x) {
	uint32_t result = SHA256::rightRotate(_x, 6) ^ SHA256::rightRotate(_x, 11) ^ SHA256::rightRotate(_x, 25);
	return result;
}

uint32_t SHA256::choose(uint32_t _x, uint32_t _y, uint32_t _z) {
	uint32_t result = (_x & _y) ^ (~_x & _z);
	return result;
}

uint32_t SHA256::majority(uint32_t _x, uint32_t _y, uint32_t _z) {
	uint32_t result = (_x & _y) ^ (_x & _z) ^ (_y & _z);
	return result;
}

int main() {
    
	SHA256 sha256;
	
	vector<uint8_t> encodedMessage = sha256.messagePreProcess("Hello World");
	for (uint8_t element : encodedMessage) {
		cout << bitset<8>(element) << endl;
	}
	
	// 	vector<uint32_t> hash = sha256.SHA256Process(encodedMessage);

	// 	cout << hash << endl;


}
