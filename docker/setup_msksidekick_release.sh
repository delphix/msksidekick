if [ "$#" -ne 1 ]; then
  echo "Usage: $0 VERSION" >&2
  exit 1
fi

release=$1

unzip linux7build.zip
rm linux7build.zip

unzip linux8build.zip
rm linux8build.zip

unzip osxbuild.zip
rm osxbuild.zip

unzip ubuntu18build.zip
rm ubuntu18build.zip

unzip windowsbuild.zip
rm windowsbuild.zip