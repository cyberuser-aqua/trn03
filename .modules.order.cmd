cmd_/home/aqua/trn03/modules.order := {   echo /home/aqua/trn03/aquadev.ko; :; } | awk '!x[$$0]++' - > /home/aqua/trn03/modules.order
