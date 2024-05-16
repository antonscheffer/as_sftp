CREATE OR REPLACE PACKAGE BODY as_sftp_keymgmt_security IS
    FUNCTION check_caller
    RETURN BOOLEAN
    IS
        v_owner varchar2(1024);
        v_name varchar2(1024);
        v_depth BINARY_INTEGER := UTL_CALL_STACK.dynamic_depth;
    BEGIN
        -- this function is 1. 2 is the "security" function who calls us. 
        -- 3 and 4 are involved with the Oracle fine grained access control implementation.
        -- The 5th entry in the call stack is the procedure that initiated the SELECT,INSERT,UPDATE, or DELETE
        -- SQL call.
        IF v_depth < 5 THEN
            DBMS_OUTPUT.put_line('security check found not called by &&compile_schema..AS_SFTP.');
            dbms_output.put_line('call stack less than 5: '||v_depth);
            DBMS_OUTPUT.put_line('Not allowing query or dml.');
            RETURN FALSE;
        END IF;
        v_owner := UTL_CALL_STACK.owner(5);
        v_name := UTL_CALL_STACK.concatenate_subprogram(UTL_CALL_STACK.subprogram(5));
        IF v_owner = '&&compile_schema.' 
            --AND v_name = 'AS_SFTP.'||p_name 
            AND v_name LIKE 'AS_SFTP.%'
        THEN 
            RETURN TRUE;
        ELSE 
            DBMS_OUTPUT.put_line('security check found not called by &&compile_schema..AS_SFTP.');
            --DBMS_OUTPUT.put_line('security check found not called by &&compile_schema..AS_SFTP.'||p_name);
            DBMS_OUTPUT.put_line('was called by owner: '||v_owner||' name: '||v_name);
            DBMS_OUTPUT.put_line('Not allowing query or dml.');
            RETURN FALSE;
        END IF;
    END check_caller
    ;

    --
    -- it may have been OK to simply assign "check_caller" to all of the security directives,
    -- but this is how it is done in the documentation.
    --
    -- For the private_keys table
    FUNCTION user_data_select_security (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2
    IS
    BEGIN
        RETURN CASE WHEN check_caller THEN NULL ELSE '1=0' END;
    END user_data_select_security
    ;

    FUNCTION user_data_insert_security (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2
    IS
    BEGIN
        RETURN CASE WHEN check_caller THEN NULL ELSE '1=0' END;
    END user_data_insert_security
    ;
    FUNCTION user_data_update_security (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2
    IS
    BEGIN
        RETURN CASE WHEN check_caller THEN NULL ELSE '1=0' END;
    END user_data_update_security
    ;

    FUNCTION user_data_delete_security (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2
    IS
    BEGIN
        RETURN CASE WHEN check_caller THEN NULL ELSE '1=0' END;
    END user_data_delete_security
    ;


    -- For the known_hosts table
    FUNCTION user_data_select_security_kh (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2
    IS
    BEGIN
        RETURN CASE WHEN check_caller THEN NULL ELSE '1=0' END;
    END user_data_select_security_kh
    ;

    FUNCTION user_data_insert_security_kh (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2
    IS
    BEGIN
        RETURN CASE WHEN check_caller THEN NULL ELSE '1=0' END;
    END user_data_insert_security_kh
    ;
    FUNCTION user_data_update_security_kh (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2
    IS
    BEGIN
        RETURN CASE WHEN check_caller THEN NULL ELSE '1=0' END;
    END user_data_update_security_kh
    ;

    FUNCTION user_data_delete_security_kh (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2
    IS
    BEGIN
        RETURN CASE WHEN check_caller THEN NULL ELSE '1=0' END;
    END user_data_delete_security_kh
    ;

END as_sftp_keymgmt_security;
/
show errors
