Generation fuzzer for tar archive for the UCL Computer Security Course

## How to use

### CLION

Open the project in `CLION` and build with default CMakeLists.txt

**IMPORTANT**: In `CLION`top right corner look for the build configurations 3 vertical dotted button -> `More Actions` -> `Edit` (Configuration) -> **Check the box labeled** `Emulate terminal in the output console`

Add argument to the tar_fuzzer executable

```
./tar_fuzzer <path_to_tar_extractor>
```

### Debian/Kali (wsl)

```bash
sudo apt update
sudo apt install -y cmake gcc make
mkdir -p build && cd build
cmake .. -G "Unix Makefiles"
make
```

Then execute the tar_fuzzer with the following command:

```
./tar_fuzzer <path_to_tar_extractor>
```
