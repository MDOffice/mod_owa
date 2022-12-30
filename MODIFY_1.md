#### modowa.h
to *struct owa_context* add 
    before *ora_before* :
    
    char           *ora_valid;


#### modowa.c
to *static const command_rec ora_commands[]* add
    before *OwaBefore* :

	ARG_PATTERN("OwaValidation",   ARG_SET(ora_valid),  ACCESS_CONF,   TAKE1,
            "OwaValidation <valid procedure>"                          ),


#### owahand.c
to *owa_handle_request* add
   before FIRST *if (octx->ora_before)* :
 
    if (octx->ora_valid) stmtlen += (str_length(octx->ora_valid) + 23);

   before SECOND *if (octx->ora_before)* :
 
    if (octx->ora_valid)
    {
        sptr += str_concat(sptr, 0, "  if ", -1);
        sptr += str_concat(sptr, 0, octx->ora_valid, -1);
        sptr += str_concat(sptr, 0, "('", -1);
        sptr += str_concat(sptr, 0, spath, -1);
        sptr += str_concat(sptr, 0, "') = false then", -1);
        sptr += str_concat(sptr, 0,
                           (char *)((spflag == 4) ? "\n     " : "\n   "), -1);
        sptr += str_concat(sptr, 0, "return;", -1);
        sptr += str_concat(sptr, 0, "end if", -1);
        sptr += str_concat(sptr, 0,
                           (char *)((spflag == 4) ? ";\n    " : ";\n  "), -1);
    }
