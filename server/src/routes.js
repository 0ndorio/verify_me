"use strict";

import routes_ecdsa_andreev from "./ecdsa_andreev/routes"
import routes_ecdsa_butun from "./ecdsa_butun/routes"
import routes_rsa from "./rsa/routes_rsa"

const routes_api = {
  ecdsa: {
    andreev: routes_ecdsa_andreev,
    butun: routes_ecdsa_butun
  },
  rsa: routes_rsa
};

export default routes_api;