cmd_/home/aqua/trn03/Module.symvers := sed 's/\.ko$$/\.o/' /home/aqua/trn03/modules.order | scripts/mod/modpost -m -a  -o /home/aqua/trn03/Module.symvers -e -i Module.symvers   -T -
