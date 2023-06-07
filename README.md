# SHA256
### Rougly Implemented. Need to be trimmed and cleaned. But anyway, it works!
Can I implement SHA 256 hashing algorithm in C++?

> My professor used to tell me, if you learn, then you try to use that everywhere you wish or have to.


<br>
<br>
Very ez to use due to the encapsulation:

```c++
int main() {
    
	SHA256 getSHA256Hash;
	
	cout << getSHA256Hash.getSHA256HexHash("Hello World!") << endl;
	cout << getSHA256Hash.getSHA256HexHash("F#ck up the tomorrow's exam LMAO :)") << endl;


}
```

```
7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
61a5069de15ed85346c3c589c96257a9bc5690fa7f913183946217cb981e7303
```
