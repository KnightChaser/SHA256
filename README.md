# SHA256
### Rougly Implemented. Need to be trimmed and cleaned. But anyway, it works!
Can I implement SHA 256 hashing algorithm in C++?

> My professor used to tell me, if you learn, then you try to use that everywhere you wish or have to.


<br>
<br>

Very ez to use due to the encapsulation. (Refer to the following example usage)

```c++
int main() {

	SHA256 sha256;

	cout << sha256.getSHA256HexHash("hello world!", "text") << endl;	// 7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9
	cout << sha256.getSHA256HexHash("./KMSRoon.png", "binary") << endl;	// c01cd743c5749e0d98731923b8bc94dec5c29d2d297b3fce6d7602d1803cb7a7


}
```

```
7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9
c01cd743c5749e0d98731923b8bc94dec5c29d2d297b3fce6d7602d1803cb7a7
```
Supports both text(consisted of ASCII data) and binary(pictures, raw binary data, dll files, etc. You can run this implementation of SHA256 by putting their locations.) inputs. However, this code is not written for performancing to be adopted in the real applications. It's for learning or education.
