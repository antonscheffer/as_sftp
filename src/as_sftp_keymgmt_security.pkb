CREATE OR REPLACE PACKAGE BODY as_sftp_keymgmt_security IS
    FUNCTION check_caller(p_name VARCHAR2)
    RETURN BOOLEAN
    IS
        v_owner varchar2(1024);
        v_name varchar2(1024);
        v_depth BINARY_INTEGER := UTL_CALL_STACK.dynamic_depth;
    BEGIN
        IF v_depth < 5 THEN
            DBMS_OUTPUT.put_line('security check found not called by &&compile_schema..AS_SFTP.'||p_name);
            dbms_output.put_line('call stack less than 5: '||v_depth);
            DBMS_OUTPUT.put_line('Not allowing query or dml.');
            RETURN FALSE;
        END IF;
        v_owner := UTL_CALL_STACK.owner(5);
        v_name := UTL_CALL_STACK.concatenate_subprogram(UTL_CALL_STACK.subprogram(5));
        IF v_owner = '&&compile_schema.' AND v_name = 'AS_SFTP.'||p_name THEN 
            RETURN TRUE;
        ELSE 
            DBMS_OUTPUT.put_line('security check found not called by &&compile_schema..AS_SFTP.'||p_name);
            DBMS_OUTPUT.put_line('was called by owner: '||v_owner||' name: '||v_name);
            DBMS_OUTPUT.put_line('Not allowing query or dml.');
            RETURN FALSE;
        END IF;
    END check_caller
    ;

    FUNCTION user_data_select_security (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2
    IS
    BEGIN
        RETURN CASE WHEN check_caller('GET_PRIV_KEY') THEN NULL ELSE '1=0' END;
    END user_data_select_security
    ;

    FUNCTION user_data_insert_security (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2
    IS
    BEGIN
        RETURN CASE WHEN check_caller('INSERT_PRIV_KEY') THEN NULL ELSE '1=0' END;
    END user_data_insert_security
    ;
    FUNCTION user_data_update_security (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2
    IS
    BEGIN
        RETURN CASE WHEN check_caller('UPDATE_PRIV_KEY') THEN NULL ELSE '1=0' END;
    END user_data_update_security
    ;

    FUNCTION user_data_delete_security (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2
    IS
    BEGIN
        RETURN CASE WHEN check_caller('DELETE_PRIV_KEY') THEN NULL ELSE '1=0' END;
    END user_data_delete_security
    ;
END as_sftp_keymgmt_security;
/
show errors
