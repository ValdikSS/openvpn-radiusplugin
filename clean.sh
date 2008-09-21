make clean
find ./ -name CVS -exec rm -rf {} \;
find ./ -name *~ -exec rm -rf {} \;
find ./ -name *kdevelop* -exec rm -rf {} \;
rm main

