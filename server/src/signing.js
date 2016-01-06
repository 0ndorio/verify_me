import { rsa_key, ecc_key} from "./server_keys"

export function sign_blinded_rsa_message()
{
  console.log(rsa_key);
}

export function sign_blinded_ecc_mesage()
{
  console.log(ecc_key);
}
