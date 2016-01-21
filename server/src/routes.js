"use strict";

import routes_ecdsa_andreev from "./ecdsa_andreev/routes"
import routes_rsa from "./rsa/routes_rsa"

const routes_api = {
  ecdsa: {
    andreev: routes_ecdsa_andreev
  },
  rsa: routes_rsa
};

export default routes_api;