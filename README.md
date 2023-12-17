# Keymath
keymath written in C for ECC and bitcoin

```
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [keymath](https://github.com/albertobsd/ecctools#keymath)


## How to download and run the code?

```
apt update && apt upgrade
apt install root-repo
apt install git -y
apt install build-essential -y
apt install libssl-dev
apt install libgcrypt20-dev
apt install libgmp-dev

```

Clone this repository

```
git clone https://github.com/adz2323/keymath.git
```

Compile:

```
make
```



## keymath with Hashtable to cross reference Known Publickeys

Keymath is basically an arithmetic calculator por publickeys with only four operations:

+ addition
- subtration
x multiplication by an scalar number
/ division by an scalar number
-m Continuous mode
-R random mode (-R 1234:2468)

previous example:

```./keymath 03a301697bdfcd704313ba48e51d567543f2a182031efd6915ddc07bbcc4e16070 / 4```

output:
```Result: 03f694cbaf2b966c1cc5f7f829d3a907819bc70ebcc1b229d9e81bda2712998b10```


this is the first line of the keydivision example, their privatekey is `0x1000000000000000000000000000000` bewteen 4 equals to `0x400000000000000000000000000000`


```./keymath 03f694cbaf2b966c1cc5f7f829d3a907819bc70ebcc1b229d9e81bda2712998b10 / 4```

output:
```Result: 02e80fea14441fb33a7d8adab9475d7fab2019effb5156a792f1a11778e3c0df5d```

from here you can do your calculations by your self

### multiplication by an scalar number

The multiplication and the division only can be done with a number you can't multiply or divide two publickeys

```./keymath 033ab6bde10cd3ac0cd06883fa66f0b0e3eb1309c0534b812286e2a30ca540db99 x 64```


```Result: 03a301697bdfcd704313ba48e51d567543f2a182031efd6915ddc07bbcc4e16070```


```./keymath 033ab6bde10cd3ac0cd06883fa66f0b0e3eb1309c0534b812286e2a30ca540db99 - -R 1:100 -m```
 Generates random Numbers between 1-100


