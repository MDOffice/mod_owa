#include <stdio.h>
#include <modowa.h>

int main(argc, argv)
int   argc;
char *argv[];
{
  char     *evname = "MODOWA_SCRAMBLE";
  char     *scramble = os_env_get(evname);
  char     *connstr;
  char     *tempstr;
  char     *hexstr;
  int       slen;
  int       xlen;
  un_long   sec;
  un_long   musec;

  if (!scramble)
  {
    printf("%s can't read environment variable %s\n", argv[0], evname);
    return(0);
  }
  xlen = str_length(scramble);

  if (xlen == 0)
  {
    printf("%s required %s to be set\n", argv[0], evname);
    return(0);
  }

  if (argc < 2)
  {
    printf("Usage: %s <dbconnectstr>\n", argv[0]);
    return(0);
  }

  sec = os_get_time(&musec);
  sec ^= (musec << 24);
  sec ^= ((musec << 16) & 0xFF0000);
  sec ^= ((musec << 8) & 0xFF00);
  sec ^= (musec & 0xFF);

  slen = str_length(argv[1]);

  connstr = (char *)os_alloca(slen + 4 + 1);
  tempstr = (char *)os_alloca(slen + 4 + 1);
  hexstr = (char *)os_alloca((slen + 4) * 2 + 1);

  connstr[3] = (char)(sec & 0xFF);
  sec >>= 8;
  connstr[2] = (char)(sec & 0xFF);
  sec >>= 8;
  connstr[1] = (char)(sec & 0xFF);
  sec >>= 8;
  connstr[0] = (char)(sec & 0xFF);

  mem_copy(connstr + 4, argv[1], slen + 1);

  slen += 4;

  util_scramble(scramble, xlen, connstr, slen, tempstr, 0);
  str_btox((void *)tempstr, hexstr, slen);
  hexstr[slen * 2] = '\0';

  mem_zero(tempstr, slen);
  slen = str_xtob(hexstr, (void *)tempstr);
  mem_zero(connstr, slen);

  util_scramble(scramble, xlen, tempstr, slen, connstr, 1);
  connstr[slen] = '\0';

  printf("Original  = [%s]\n", connstr + 4);
  printf("Scrambled = [%s]\n", hexstr);

  return(0);
}
