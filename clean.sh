make clean
find ./ -name CVS -exec rm -rf {} \;
find ./ -name "*~" -exec rm -rf {} \;
find ./ -name "*kdevelop*" -exec rm -rf {} \;
rm -rf radiusplugin_v2.0a 
rm main

