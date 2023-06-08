// Written in C++ 20
// @KnightChaser

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cassert>
#include <cmath>
#include <array>
#include <sstream>
#include <iomanip>
using namespace std;

class SHA256 {
private:
public:

	vector<uint8_t>     messagePreProcess(vector<uint8_t>& message);
	array<uint32_t, 8>  makeInitializeHashValues();                                             // H[0] (Size: 8)
	vector<uint32_t>    makeInitializeRoundConstants();                                         // K[x] (Size: 64)
	array<uint32_t, 64> createWArray(const uint8_t(&M)[64]);									// W & MEXP(Message Expansion)
	array<uint32_t, 8>  SHA256Round(array<uint32_t, 8>const& Hs, uint32_t Ks, uint32_t Ws);     // compressing data
	array<uint32_t, 8>  SHA256Process(vector<uint8_t> const& message);
	string              SHA256HexConvert(array<uint32_t, 8> const& SHA256RawDigest);
	string				getSHA256HexHash(const string input, const string type);

	uint32_t            rightRotate(uint32_t _x, uint32_t n);
	uint32_t            changeEndian(uint32_t x);
	uint64_t            changeEndian(uint64_t x);
	uint32_t            sigma0(uint32_t _x);
	uint32_t            sigma1(uint32_t _x);
	uint32_t            bigSigma0(uint32_t _x);
	uint32_t            bigSigma1(uint32_t _x);
	uint32_t            choose(uint32_t _x, uint32_t _y, uint32_t _z);
	uint32_t            majority(uint32_t _x, uint32_t _y, uint32_t _z);

	vector<uint8_t>		textToUINT8T(const string messageInput);								// For text(ASCII) input
	vector<uint8_t>		binaryToUINT8T(const string filePath);									// For binary input
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

// Choose function
// Ch(x, y, z): At the x input chooses if the output is from y or from z.
// More precisely, for each bit index, that result bit is according to the bit from y (or respectively from z)
// at this index, depending on if the bit from x at this index is 1 (or respectively 0).
uint32_t SHA256::choose(uint32_t _x, uint32_t _y, uint32_t _z) {
	uint32_t result = (_x & _y) ^ (~_x & _z);
	return result;
}

// Majority function
// Maj(x, y, z): For each bit index, that result bit is according to the
// majority of the 3 inputs bits for x, y, and z at this index
//  -> Take a bit of majority among the input values which are x, y, and z.
uint32_t SHA256::majority(uint32_t _x, uint32_t _y, uint32_t _z) {
	uint32_t result = (_x & _y) ^ (_x & _z) ^ (_y & _z);
	return result;
}

// Message preprocessing before SHA256's 64-Round calculation
//  1. Get the original message itself and append a single "1" bit behind that.
//  2. Add padding by appending "0" bits to fit the message is the multiple of 512 (bits).
//  3. At the last 64 bits, write a bit length of the original message.
// After preprocessing, the processed message digest should be 512 bits long.
//  ** Process as Big-Endian way **
vector<uint8_t> SHA256::messagePreProcess(vector<uint8_t>& message) {

	auto messageLength = static_cast<uint64_t>(message.size());             // bit length of the given message

	// (Step 1)
	message.push_back(0b10000000);

	// (Step 2)
	//  *but be sure to remain the space of (Step 3)
	int zeroPaddingCount = 64 - (((messageLength % 64) + 9) % 64);
	if (zeroPaddingCount == 64)
		zeroPaddingCount = 0;

	for (int _ = 0; _ < zeroPaddingCount; ++_)
		message.push_back(0b00000000);

	// (Step 3)
	assert(messageLength <= UINT64_MAX / 8);                                                // must be assured
	uint64_t bitLengthInBigEndian = SHA256::changeEndian((uint64_t)messageLength * 8);      // byte to bit
	auto bitLengthDataPtr = reinterpret_cast<uint8_t *>(&bitLengthInBigEndian);

	message.insert(end(message), bitLengthDataPtr, bitLengthDataPtr + 8);                   // put the length data at the end
	assert(message.size() % 64 == 0);                                                       // verify size

	return message;

}


// Initializiation Constants H[0]
// To calculate those Initialize Hash Values,
// get the square root(sqrt()) values of smallest 8 prime numbers(2, 3, 5, 7, 11, 13, 17, 19),
// then extract the following 32 bits since the decimal point(.)
array<uint32_t, 8> SHA256::makeInitializeHashValues() {

	// h0 = 0x6a09e667
	// h1 = 0xbb67ae85
	// h2 = 0x3c6ef372
	// h3 = 0xa54ff53a
	// h4 = 0x510e527f
	// h5 = 0x9b05688c
	// h6 = 0x1f83d9ab
	// h7 = 0x5be0cd19

	const int primesForSHA256Hx[] = { 2, 3, 5, 7, 11, 13, 17, 19 };
	static_assert(sizeof(primesForSHA256Hx) / sizeof(*primesForSHA256Hx) == 8, "");     // Should be assured

	array<uint32_t, 8> HValues;

	for (int _seq = 0; _seq < 8; ++_seq) {
		double Hx = sqrt(primesForSHA256Hx[_seq]);

		Hx -= static_cast<uint32_t>(Hx);                                                // remove numbers >= 1
		Hx *= pow(16, 8);                                                               // extract 32 bit since the decimal point

		HValues[_seq] = static_cast<uint32_t>(Hx);
	}

	return HValues;
}

// Constant K
// To calculate those Initialize Hash Values,
// get the cubic root(cbrt()) values of smallest 64 prime numbers(2, 3, 5, 7 ... 283, 293, 307, 311),
// then extract the following 32 bits since the decimal point(.)
vector<uint32_t> SHA256::makeInitializeRoundConstants() {

	// K[0], K[1], K[2] ... K[63]
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

		Kx -= static_cast<uint32_t>(Kx);                                                // remove numbers >= 1
		Kx *= pow(16, 8);                                                               // extract 32 bit since the decimal point

		KValues.push_back(static_cast<uint32_t>(Kx));

	}

	return KValues;

}


// Message scheduling

// W is a set of values derived from message chuck(has been preprocesed) which size is multiple of 512 bits long
// Each W should be 32 bits long
//  1. Divide the message chuck into 16 pieces to make each piece is 32 bits long. (W[0] ~ W[15])
//  2. Other chucks will be elicited accordng to the predefined MEXP(Message Expansion Function) procedure.

// [W(i - 2)] -----sigma1---|
// [W(i - 7)] --------------|==(append)==> W[i] (for 16 <= i <= 63)
// [W(i - 15)] ----sigma0---|
// [W(i - 16)] -------------|

// W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];   (for 16 <= i <= 63)

// ** Process as Big-Endian way **
array<uint32_t, 64> SHA256::createWArray(const uint8_t(&M)[64]) {

	// 2,048 bits long
	array<uint32_t, 64> WValues;

	// For W[0] ~ W[15]
	for (int _seq = 0; _seq < 16; ++_seq)
		WValues[_seq] = SHA256::changeEndian(reinterpret_cast<uint32_t const&>(M[_seq * 4]));   // 8bit * 4 = 32bit

	// For W[16] ~ W[63]
	for (int _seq = 16; _seq < 64; ++_seq)
		WValues[_seq] = SHA256::sigma1(WValues[_seq - 2]) + WValues[_seq - 7] + SHA256::sigma0(WValues[_seq - 15]) + WValues[_seq - 16];

	return WValues;

}

// Compression (equivalent to 1 separate SHA256 round which will be executed for 64 times.)

//                          Splitted chuck Ws stands for the output from message scheduling (W and MEXP)
//                                                                              |
//                                                                              ▼
array<uint32_t, 8> SHA256::SHA256Round(array<uint32_t, 8>const& Hs, uint32_t Ks, uint32_t Ws) {

	array<uint32_t, 8> nextH;

	auto majority = SHA256::majority(Hs[0], Hs[1], Hs[2]);
	auto choose = SHA256::choose(Hs[4], Hs[5], Hs[6]);
	auto s = Ks + SHA256::bigSigma1(Hs[4]) + choose + Hs[7] + Ws;

	nextH[0] = SHA256::bigSigma0(Hs[0]) + majority + s;
	nextH[1] = Hs[0];
	nextH[2] = Hs[1];
	nextH[3] = Hs[2];
	nextH[4] = Hs[3] + s;
	nextH[5] = Hs[4];
	nextH[6] = Hs[5];
	nextH[7] = Hs[6];

	return nextH;

}

// Real process, including 64 rounds to elicit the SHA256 hash digest output.

// With H values, K values, W values and the overall round function,
// Process SHA-256 process with the given data.
array<uint32_t, 8> SHA256::SHA256Process(vector<uint8_t> const& message) {

	assert(message.size() % 64 == 0);                               // should be guaranteed for proper process

	const auto Ks = SHA256::makeInitializeRoundConstants();
	auto digest = SHA256::makeInitializeHashValues();
	const auto chuckQty = message.size() / 64;                      // 64 Bytes = 512 bits. Which means how long is the data, in chuck size quantity.

	// Repeat SHA256 calculation until the message chuck is exhausted.
	// So SHA256 algorithm ensures the output length will be 256 bits long regardless of the input length.
	for (int _seq = 0; _seq < chuckQty; ++_seq) {
		auto Ws = SHA256::createWArray(reinterpret_cast<const uint8_t(&)[64]>(message[_seq * 64]));   // get array<uint32_t, 64>
		auto Hs = digest;

		// Each chuck is assigned to execute round function for 64 times in a row.
		for (int _round_seq = 0; _round_seq < 64; ++_round_seq)
			Hs = SHA256::SHA256Round(Hs, Ks[_round_seq], Ws[_round_seq]);

		// After completion for the current chuck, concatenate.
		for (int _digest_seq = 0; _digest_seq < 8; ++_digest_seq)
			digest[_digest_seq] += Hs[_digest_seq];
	}

	return digest;

}

// Convert <uint32t, 8> formatted raw SHA256 hash digest to hex string
string SHA256::SHA256HexConvert(array<uint32_t, 8> const& SHA256RawDigest) {

	stringstream SHA256HexDigest;

	for (auto element : SHA256RawDigest)
		SHA256HexDigest << std::setfill('0') << std::setw(8) << hex << element;

	return SHA256HexDigest.str();
}

// Text to uint32_t (for SHA256 processing)
vector<uint8_t> SHA256::textToUINT8T(const string messageInput) {

	vector<uint8_t> message(messageInput.begin(), messageInput.end());
	return message;

}

// Binary to uint32_t (for SHA256 processing)
// Include file opening and handling from given file path(location).
vector<uint8_t> SHA256::binaryToUINT8T(const string filePath) {

	ifstream file;
	file.open(filePath, ios::in | ios::binary);

	if (!file)
		throw filePath;

	vector<uint8_t> UTIN8VECTOR((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());

	file.close();

	return UTIN8VECTOR;

}

// Integrate the whole process to make it easy to use.
// Decisional behavior whether the given mode is for text or for binary files.
string SHA256::getSHA256HexHash(const string input, const string type) {

	if (type != "text" && type != "binary")
		return "Only supports text or binary input mode";

	SHA256 sha256;

	vector<uint8_t> message;

	if (type == "text")
		message = sha256.textToUINT8T(input);
	else if (type == "binary") {
		try {
			message = sha256.binaryToUINT8T(input);
		} catch (string invalidFilePath) {
			string errorMessage = "Can't open the file: " + invalidFilePath + "\n";
			return errorMessage;
		}
	}

	vector<uint8_t> encodedMessage = sha256.messagePreProcess(message);
	auto digest = sha256.SHA256Process(encodedMessage);
	return sha256.SHA256HexConvert(digest);                 // hexadecimal form of SHA-256

}

int main() {

	SHA256 sha256;

	cout << sha256.getSHA256HexHash("hello world!", "text") << endl;	// 7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9
	cout << sha256.getSHA256HexHash("./KMSRoon.png", "binary") << endl;	// c01cd743c5749e0d98731923b8bc94dec5c29d2d297b3fce6d7602d1803cb7a7


}
