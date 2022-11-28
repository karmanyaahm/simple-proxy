{ lib, fetchFromGitHub, buildGoModule, ... }:

buildGoModule rec {
  pname = "proxy";
  version = "0.0.1";

  src = fetchFromGitHub {
    owner = "karmanyaahm";
    repo = "simple-proxy";
    rev = "main";
    sha256 = "ErWqeMcBbmhwIno/9riSjfHYbh5qIBOOqRZKUTR/7mM=";
  };

vendorSha256 = "JTEZxWL4VVhyxjsiAtr8ttkXETERZp4P141LMBPehZI=";
}

