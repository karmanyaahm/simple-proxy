{ lib, fetchFromGitHub, buildGoModule, pkgs, config, ... }:
with lib;                      
let
  cfg = config.services.wsproxy;
in {
  options.services.wsproxy = {
    enable = mkEnableOption "hello service";

txaddr = mkOption {
   type = types.str;
   default = "";
  description = "";
};
    };
  
  config = mkIf cfg.enable {

  nixpkgs.overlays = [
    (self: super: {
      wsproxy = self.callPackage buildGoModule rec {
  pname = "proxy";
  version = "0.0.1";

  src = fetchFromGitHub {
    owner = "karmanyaahm";
    repo = "simple-proxy";
    rev = "main";
    sha256 = "ErWqeMcBbmhwIno/9riSjfHYbh5qIBOOqRZKUTR/7mM=";
  };

vendorSha256 = "JTEZxWL4VVhyxjsiAtr8ttkXETERZp4P141LMBPehZI=";
} {};
    })
  ];


    systemd.services.wsproxy = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.wsproxy}/bin/proxy -c";
    }; 


 };
}
