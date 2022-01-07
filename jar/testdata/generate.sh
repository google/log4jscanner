#!/bin/bash -e

# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

echo '#!/bin/bash
file_path=`realpath $0`
exec java -jar $file_path "$@"
' > helloworld-executable
cat helloworld.jar >> helloworld-executable
chmod +x helloworld-executable

echo '#!/bin/bash
file_path=`realpath $0`
exec java -jar $file_path "$@"
' > vuln-class-executable
cat vuln-class.jar >> vuln-class-executable
chmod +x vuln-class-executable

mkdir -p tmp
dd if=/dev/zero of=tmp/400mb bs=1M count=400
zip 400mb.jar tmp/400mb
rm -rf tmp

zip 400mb_jar_in_jar.jar 400mb.jar
