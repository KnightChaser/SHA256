#include <iostream>
#include <vector>
#include <string>
#include <assert.h> 
#include <bitset>
#include <cmath>
using namespace std;

template <typename Tx>
ostream& operator<< (ostream& os, vector<Tx> inputVector) {

	for (Tx element : inputVector)
		os << element << " ";

	return os;

}

long unsigned int convertToBigEndian(long unsigned int value) {
    long unsigned int result = 0;

    for (size_t i = 0; i < sizeof(long unsigned int); i++) {
        result <<= 8;
        result |= (value & 0xFF);
        value >>= 8;
    }

    return result;
}

class SHA256 {
private:
public:
	vector<uint8_t> messagePreProcess(const string messageInput);
	vector<uint32_t> makeInitializeHashValues();
};

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
	uint64_t bitLengthInBigEndian = convertToBigEndian(messageLength * 8);      // byte to bit
	auto bitLengthDataPtr = reinterpret_cast<uint8_t *>(&bitLengthInBigEndian);

	message.insert(end(message), bitLengthDataPtr, bitLengthDataPtr + 8);       // put the length data
	assert(message.size() % 64 == 0);                                           // verify

	for (uint8_t element : message) {
		cout << bitset<8>(element) << endl;
	}
	
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
    const int primesForSHA256[] = { 2, 3, 5, 7, 11, 13, 17, 19 };
    static_assert(sizeof(primesForSHA256) / sizeof(*primesForSHA256) == 8);     // Should be assured
    
    vector<uint32_t> HValues;
    
    for(int _seq = 0; _seq < 8; ++_seq) {
        double Hx = sqrt(primesForSHA256[_seq]);
        
        Hx -= static_cast<uint32_t>(Hx);    // remove numbers >= 1
        Hx *= pow(16, 8);                   // extract 32 bit since the decimal point
        
        HValues.push_back(static_cast<uint32_t>(Hx));
    }
    
    return HValues;
}

int main() {

	SHA256 sha256;
// 	sha256.messagePreProcess("Hello World");

    cout << hex << sha256.makeInitializeHashValues() << endl;

}
