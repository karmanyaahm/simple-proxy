 
{lib, config, pkgs, buildGoModule, fetchFromGitHub, ... }:


let
  privateKey = "";
  serverPubKey = "";
  serverPsk = "";
  externalInterface = "wlp4s0";
  internalInterface = "enp0s25";
  externalPort = 5182;
  interfaceAddr = "10.6.0.9/24";
in
{

  networking.wireless.enable = true;
  networking.wireless.networks.BISD_Student.psk = "students";  

networking.dhcpcd.extraConfig = ''interface ${externalInterface}
metric 100'';


  boot = {    kernel = {      sysctl = {        "net.ipv4.conf.all.forwarding" = true;        "net.ipv6.conf.all.forwarding" = true;      };    };  };
  # enable NAT
  networking.nat.enable = true;
  networking.nat.externalInterface = externalInterface;
  networking.nat.internalInterfaces = [ internalInterface ];
  networking.firewall = {
    allowedUDPPorts = [ externalPort ];
  };

  networking.wireguard.interfaces = {
    wg0 = {
      ips = [ interfaceAddr ];

      listenPort = externalPort;

      privateKey = privateKey;

      table = "52240";
      

      postSetup = ''
        /run/current-system/sw/bin/iptables -A FORWARD -i ${internalInterface} -j ACCEPT
        /run/current-system/sw/bin/iptables -A FORWARD -o ${internalInterface} -j ACCEPT
        /run/current-system/sw/bin/iptables -t nat -A POSTROUTING -o ${externalInterface} -j MASQUERADE
          wg set wg0 fwmark 52240
          ip -6 rule add not fwmark 52240 table 52240
          ip -6 rule add table main suppress_prefixlength 0
          ip -4 rule add not fwmark 52240 table 52240
          ip -4 rule add table main suppress_prefixlength 0      
'';

      postShutdown = ''
        /run/current-system/sw/bin/iptables -D FORWARD -i ${internalInterface} -j ACCEPT
        /run/current-system/sw/bin/iptables -D FORWARD -o ${internalInterface} -j ACCEPT
        /run/current-system/sw/bin/iptables -t nat -D POSTROUTING -o ${externalInterface} -j MASQUERADE
                  ip -4 rule delete table 52240
          ip -4 rule delete table main suppress_prefixlength 0
          ip -6 rule delete table 52240
          ip -6 rule delete table main suppress_prefixlength 0
'';

      peers = [
        {
          publicKey = serverPubKey;
          allowedIPs = [ "0.0.0.0/0" ];
	  persistentKeepalive = 25;
          endpoint = "[::]:1050";
        }
      ];
    };
  };


  imports = [ ./proxypkg.nix ];
  services.wsproxy.enable = true;

}
