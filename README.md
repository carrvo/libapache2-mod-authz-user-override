# libapache2-mod-authz-user-override

This is meant to extend [mod_authz_user](https://github.com/apache/httpd/blob/040c577fdd854822a8ae2c7cd4b7989a9da853b8/modules/aaa/mod_authz_user.c) that is built-in to [httpd](https://httpd.apache.org/).

## Usage

```conf
# Matches all users that start with "Wor" such as "World", "Word", "Worth", et cetera
Require user-starts-with Wor
```

## License

   Originally obtained from [https://github.com/apache/httpd/blob/040c577fdd854822a8ae2c7cd4b7989a9da853b8/modules/aaa/mod_authz_user.c](https://github.com/apache/httpd/blob/040c577fdd854822a8ae2c7cd4b7989a9da853b8/modules/aaa/mod_authz_user.c) on 2025-12-17
   Changes documented within [CHANGES](./CHANGES)

   Copyright 2025 carrvo

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

