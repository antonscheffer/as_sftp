CREATE OR REPLACE package body as_sftp
is
  --
  type tp_mag is table of number index by pls_integer;
  --
  type tp_ec_point is record
    ( x tp_mag
    , y tp_mag
    , z tp_mag
    );
  type tp_ec_curve is record
    ( prime tp_mag
    , group_order tp_mag
    , a tp_mag
    , b tp_mag
    , p_plus_1_div_4 tp_mag
    , generator tp_ec_point
    , nlen pls_integer
    );
  type tp_ed_point is record
    ( x tp_mag
    , y tp_mag
    , z tp_mag
    , t tp_mag
    );
  type tp_ed_curve is record
    ( nlen pls_integer
    , l tp_mag
    , d tp_mag
    , q tp_mag
    , i tp_mag
    , b tp_ed_point
    );
  --
  type tp_ssh_channel is record
         ( my_channel number
         , server_channel number
         , max_window_size number
         , cur_window_size number
         , my_packet_size number
         , server_packet_size number
         );
  --
  type tp_name_list is table of varchar2(100 char );
  --
  type tp_pk_parameters is table of raw(3999) index by pls_integer;
  --
  function mag( p1 varchar2 )
  return tp_mag;
  --
  -- some globals
  g_con          utl_tcp.connection;
  g_ssh_channel  tp_ssh_channel;
  g_log_level    pls_integer := 3;
  g_seqn_c       number := 0;
  g_seqn_s       number := 0;
  g_encr_algo_c  varchar2(100 char);
  g_encr_algo_s  varchar2(100 char);
  g_mac_algo_c   varchar2(100 char);
  g_mac_algo_s   varchar2(100 char);
  g_compr_algo_c varchar2(100 char);
  g_compr_algo_s varchar2(100 char);
  type tp_my_globals is record
         ( excluded_kex_algos   varchar2(32767)
         , preferred_kex_algos  varchar2(32767)
         , excluded_encr_algos  varchar2(32767)
         , preferred_encr_algos varchar2(32767)
         , excluded_pkey_algos  varchar2(32767)
         , preferred_pkey_algos varchar2(32767)
         );
  my_globals tp_my_globals;
  --
  -- big integers
  ccc number := 16; -- number of nibbles
  cm number := power( 16, ccc );
  cmm number := cm-1;
  cm2 number := cm / 2;
  cmi number := power( 16, -ccc );
  c_mag_0 constant tp_mag := mag( '0' );
  c_mag_1 constant tp_mag := mag( '1' );
  c_mag_3 constant tp_mag := mag( '3' );
  c_mag_4 constant tp_mag := mag( '4' );
  --
  -- ASN1 constants
  c_INTEGER    raw(1) := '02';
  c_BIT_STRING raw(1) := '03';
  c_OCTECT     raw(1) := '04';
  c_OID        raw(1) := '06';
  c_SEQUENCE   raw(1) := '30';
  --
  -- cypher and mac globals
  g_iv_cypher_c2s raw(100);
  g_iv_cypher_s2c raw(100);
  g_key_cypher_c2s raw(256);
  g_key_cypher_s2c raw(256);
  g_key_mac_c2s raw(256);
  g_key_mac_s2c raw(256);
  g_iv_cypher_s2c_ctr number;
  --
  -- kex globals
  V_C raw(512) := utl_i18n.string_to_raw( 'SSH-2.0-as_sftp_0.088', 'US7ASCII' );
  V_S raw(512);
  g_session_id raw(100);
  --
  --
  -- Hash/MAC algorithms
  HASH_MD5   pls_integer;
  HASH_SH1   pls_integer;
  HASH_SH256 pls_integer;
  HASH_SH384 pls_integer;
  HASH_SH512 pls_integer;
  HMAC_MD5   pls_integer;
  HMAC_SH1   pls_integer;
  HMAC_SH256 pls_integer;
  HMAC_SH384 pls_integer;
  HMAC_SH512 pls_integer;
  --
  --
  -- some constants
  SSH_MSG_DISCONNECT              constant raw(1) := '01';
  SSH_MSG_IGNORE                  constant raw(1) := '02';
  SSH_MSG_UNIMPLEMENTED           constant raw(1) := '03';
  SSH_MSG_DEBUG                   constant raw(1) := '04';
  SSH_MSG_SERVICE_REQUEST         constant raw(1) := '05';
  SSH_MSG_SERVICE_ACCEPT          constant raw(1) := '06';
  SSH_MSG_KEXINIT                 constant raw(1) := '14';
  SSH_MSG_NEWKEYS                 constant raw(1) := '15';
  SSH_MSG_KEXDH_INIT              constant raw(1) := '1E';
  SSH_MSG_KEXDH_REPLY             constant raw(1) := '1F';
--
  SSH_MSG_KEX_DH_GEX_GROUP        constant raw(1) := '1F';
  SSH_MSG_KEX_DH_GEX_INIT         constant raw(1) := '20';
  SSH_MSG_KEX_DH_GEX_REPLY        constant raw(1) := '21';
  SSH_MSG_KEX_DH_GEX_REQUEST      constant raw(1) := '22';
  --
  SSH_MSG_KEX_ECDH_INIT           constant raw(1) := '1E';
  SSH_MSG_KEX_ECDH_REPLY          constant raw(1) := '1F';
  --
  SSH_MSG_USERAUTH_REQUEST        constant raw(1) := '32';
  SSH_MSG_USERAUTH_FAILURE        constant raw(1) := '33';
  SSH_MSG_USERAUTH_SUCCESS        constant raw(1) := '34';
  SSH_MSG_USERAUTH_BANNER         constant raw(1) := '35';
  SSH_MSG_USERAUTH_INFO_REQUEST   constant raw(1) := '3C';
  SSH_MSG_USERAUTH_INFO_RESPONSE  constant raw(1) := '3D';
  SSH_MSG_USERAUTH_PK_OK          constant raw(1) := '3C';
  --
  SSH_MSG_GLOBAL_REQUEST          constant raw(1) := '50';
  SSH_MSG_REQUEST_SUCCESS         constant raw(1) := '51';
  SSH_MSG_REQUEST_FAILURE         constant raw(1) := '52';
  SSH_MSG_CHANNEL_OPEN            constant raw(1) := '5A';
  SSH_MSG_CHANNEL_OPEN_CONFIRM    constant raw(1) := '5B';
  SSH_MSG_CHANNEL_OPEN_FAILURE    constant raw(1) := '5C';
  SSH_MSG_CHANNEL_WINDOW_ADJUST   constant raw(1) := '5D';
  SSH_MSG_CHANNEL_DATA            constant raw(1) := '5E';
  SSH_MSG_CHANNEL_EXTENDED_DATA   constant raw(1) := '5F';
  SSH_MSG_CHANNEL_EOF             constant raw(1) := '60';
  SSH_MSG_CHANNEL_CLOSE           constant raw(1) := '61';
  SSH_MSG_CHANNEL_REQUEST         constant raw(1) := '62';
  SSH_MSG_CHANNEL_SUCCESS         constant raw(1) := '63';
  SSH_MSG_CHANNEL_FAILURE         constant raw(1) := '64';
  --
  SSH_FXP_INIT             constant raw(1) := '01';
  SSH_FXP_VERSION          constant raw(1) := '02';
  SSH_FXP_OPEN             constant raw(1) := '03';
  SSH_FXP_CLOSE            constant raw(1) := '04';
  SSH_FXP_READ             constant raw(1) := '05';
  SSH_FXP_WRITE            constant raw(1) := '06';
  SSH_FXP_LSTAT            constant raw(1) := '07';
  SSH_FXP_FSTAT            constant raw(1) := '08';
  SSH_FXP_SETSTAT          constant raw(1) := '09';
  SSH_FXP_FSETSTAT         constant raw(1) := '0A';
  SSH_FXP_OPENDIR          constant raw(1) := '0B';
  SSH_FXP_READDIR          constant raw(1) := '0C';
  SSH_FXP_REMOVE           constant raw(1) := '0D';
  SSH_FXP_MKDIR            constant raw(1) := '0E';
  SSH_FXP_RMDIR            constant raw(1) := '0F';
  SSH_FXP_REALPATH         constant raw(1) := '10';
  SSH_FXP_STAT             constant raw(1) := '11';
  SSH_FXP_RENAME           constant raw(1) := '12';
  SSH_FXP_READLINK         constant raw(1) := '13';
  SSH_FXP_SYMLINK          constant raw(1) := '14';
  SSH_FXP_STATUS           constant raw(1) := '65';
  SSH_FXP_HANDLE           constant raw(1) := '66';
  SSH_FXP_DATA             constant raw(1) := '67';
  SSH_FXP_NAME             constant raw(1) := '68';
  SSH_FXP_ATTRS            constant raw(1) := '69';
  --
  SSH_FXF_READ             constant number := 1;
  SSH_FXF_WRITE            constant number := 2;
  SSH_FXF_APPEND           constant number := 4;
  SSH_FXF_CREAT            constant number := 8;
  SSH_FXF_TRUNC            constant number := 16;
  SSH_FXF_EXCL             constant number := 32;
  --
  SSH_FX_OK                  constant number := 0;
  SSH_FX_EOF                 constant number := 1;
  SSH_FX_NO_SUCH_FILE        constant number := 2;
  SSH_FX_PERMISSION_DENIED   constant number := 3;
  SSH_FX_FAILURE             constant number := 4;
  SSH_FX_BAD_MESSAGE         constant number := 5;
  SSH_FX_NO_CONNECTION       constant number := 6;
  SSH_FX_CONNECTION_LOST     constant number := 7;
  SSH_FX_OP_UNSUPPORTED      constant number := 8;
  SSH_FX_INVALID_HANDLE      constant number := 9;
  SSH_FX_NO_SUCH_PATH        constant number := 10;
  SSH_FX_FILE_ALREADY_EXISTS constant number := 11;
  --
  SSH_FILEXFER_ATTR_SIZE         number := 1;
  SSH_FILEXFER_ATTR_UIDGID       number := 2;
  SSH_FILEXFER_ATTR_PERMISSIONS  number := 4;
  SSH_FILEXFER_ATTR_ACMODTIME    number := 8;
  SSH_FILEXFER_ATTR_EXTENDED     number := 2147483648;
  --
  S_IFDIR constant number := 16384;
  --
  procedure log( p_msg in varchar2 )
  is
  begin
    dbms_output.put_line( p_msg );
  exception
    when others then null;
  end;
  --
  procedure info_msg( p_msg in varchar2 )
  is
  begin
    if g_log_level between 1 and 3
    then
      log( p_msg );
    end if;
  end;
  --
  procedure log_msg( p_msg in varchar2 )
  is
  begin
    if g_log_level between 1 and 2
    then
      log( p_msg );
    end if;
  end;
  --
  procedure debug_msg( p_msg in varchar2 )
  is
  begin
    if g_log_level >= 1
    then
      log( to_char( current_date, 'yyyy-mm-dd hh24:mi:ss' ) );
      log( p_msg );
    end if;
  end;
  --
  procedure error_msg( p_msg in varchar2 )
  is
  begin
    log( p_msg );
  end;
  --
  function mag( p1 varchar2 )
  return tp_mag
  is
    l number;
    n number;
    rv tp_mag;
    t1 varchar2(3999);
    cfmt1 varchar2(100) := rpad( 'X', ccc, 'X' );
  begin
    t1 := nvl( ltrim( p1, '0' ), '0' );
    l := ceil( length( t1 ) / ccc );
    t1 := lpad( t1, l * ccc, '0' );
    for i in 0 .. l - 1
    loop
      n := to_number( substr( t1, 1 + i * ccc, ccc ), cfmt1 );
      rv( l - 1 - i ) := n;
    end loop;
    return rv;
  end;
--
  function demag( p1 tp_mag )
  return varchar2
  is
    rv varchar2(3999);
    cfmt2 varchar2(100);
  begin
    if ccc = 1
    then
      cfmt2 := 'fmx';
    else
      cfmt2 := 'fm' || rpad( '0', ccc, 'x' );
    end if;
    for i in 0 .. p1.count - 1
    loop
      rv := to_char( p1( i ), cfmt2 ) || rv;
    end loop;
    return nvl( ltrim( rv, '0' ), '0' );
  end;
  --
  function requal( x tp_mag, y tp_mag )
  return boolean
  is
    rv boolean;
  begin
    if x.count != y.count
    then
      return false;
    end if;
    for i in 0 .. x.count - 1
    loop
      rv := x(i) = y(i);
      exit when not rv;
    end loop;
    return rv;
  end;
  --
  function r_greater_equal( x tp_mag, y tp_mag )
  return boolean
  is
    rv boolean := true;
    xc pls_integer := x.count;
    yc pls_integer := y.count;
  begin
    if xc > yc
    then
      return true;
    elsif xc < yc
    then
      return false;
    end if;
    for i in reverse 0 .. xc - 1
    loop
      exit when x(i) > y(i);
      if x(i) < y(i)
      then
        rv := false;
        exit;
      end if;
    end loop;
    return rv;
  end;
  --
  function radd( x tp_mag, y tp_mag )
  return tp_mag
  is
    c number;
    t number;
    rv tp_mag;
    xc pls_integer := x.count;
    yc pls_integer := y.count;
  begin
    if xc < yc
    then
      return radd( y, x );
    end if;
    c := 0;
    for i in 0 .. yc - 1
    loop
      t := x(i) + y(i) + c;
      if t >= cm
      then
        t := t - cm;
        c := 1;
      else
        c := 0;
      end if;
      rv(i) := t;
    end loop;
    for i in yc .. xc - 1
    loop
      t := x(i) + c;
      if t >= cm
      then
        t := t - cm;
        c := 1;
      else
        c := 0;
      end if;
      rv(i) := t;
    end loop;
    if c > 0
    then
      rv( xc ) := 1;
    end if;
    return rv;
  end;
  --
  function rsub( p1 tp_mag, p2 tp_mag )
  return tp_mag
  is
    b number;
    t number;
    rv tp_mag;
  begin
    b := 0;
    for i in 0 .. p2.count - 1
    loop
      t := p1( i ) - p2( i ) - b;
      if t < 0
      then
        b := 1;
        t := t + cm;
      else
        b := 0;
      end if;
      rv( i ) := t;
    end loop;
    for i in p2.count .. p1.count - 1
    loop
      t := p1( i ) - b;
      if t < 0
      then
        b := 1;
        t := t + cm;
      else
        b := 0;
      end if;
      rv( i ) := t;
    end loop;
    while rv( rv.last ) = 0 and rv.count > 1
    loop
      rv.delete( rv.last );
    end loop;
    if rv.count = 0
    then
      rv(0) := 0;
    end if;
    return rv;
  end;
  --
  function nsub( x tp_mag, y number )
  return tp_mag
  is
    b number;
    s tp_mag := x;
  begin
    b := y;
    for i in 0 .. s.count - 1
    loop
      s( i ) := s( i ) - b;
      if s( i ) < 0
      then
        b := 1;
        s( i ) := s( i ) + cm;
      else
        exit;
      end if;
    end loop;
    return s;
  end;
  --
  function nmul( x tp_mag, y number )
  return tp_mag
  is
    t number;
    c number := 0;
    ci pls_integer;
    rv tp_mag := x;
  begin
    for i in 0 .. rv.count - 1
    loop
      t := rv(i) * y + c;
      c := trunc( t * cmi );
      rv(i) := t - c * cm;
    end loop;
    if c > 0
    then
      rv(rv.count) := c;
    end if;
    return rv;
  end;
  --
  function rmul( x tp_mag, y tp_mag )
  return tp_mag
  is
    t number;
    c number;
    ci pls_integer;
    m tp_mag;
  begin
    for i in 0 .. y.count + x.count - 2
    loop
      m(i) := 0;
    end loop;
    for yi in 0 .. y.count - 1
    loop
      c := 0;
      for xi in 0 .. x.count - 1
      loop
        ci := xi+yi;
        t := m(ci) + x(xi) * y(yi) + c;
        c := trunc( t * cmi );
        m(ci) := t - c * cm;
      end loop;
     if c > 0
      then
        m( ci + 1 ) := c;
      end if;
    end loop;
    return m;
  end;
  --
  function xmod( x tp_mag, y tp_mag )
  return tp_mag
  is
    xc number := x.count;
    yc number := y.count;
    rv tp_mag;
    ly tp_mag;
    dq tp_mag;
    l_gt boolean;
    d number;
    d2 number;
    tmp number;
    r number;
    sf number;
    --
    procedure sub( x in out tp_mag, y tp_mag, p number )
    is
      b number := 0;
    begin
      for i in p .. p + y.count - 1
      loop
        x(i) := x(i) - y( i - p ) - b;
        if x(i) < 0
        then
          x(i) := x(i) + cm;
          b := 1;
        else
          b := 0;
        end if;
      end loop;
    end;
    --
    function ge( x tp_mag, y tp_mag, p number )
    return boolean
    is
      l_ge boolean := true;
    begin
      for i in reverse p .. p + y.count - 1
      loop
        case sign( x(i) - y( i - p ) )
          when 1 then
            exit;
          when -1 then
            l_ge := false;
            exit;
          else null;
        end case;
      end loop;
      return l_ge;
    end;
  --
  begin
    if xc < yc
    then
      return x;
    end if;
    if xc = yc
    then
      for i in reverse 0 .. xc - 1
      loop
        if x( i ) > y( i )
        then
          l_gt := true;
          exit;
        elsif x( i ) < y( i )
        then
          return x;
        end if;
      end loop;
      if l_gt is null
      then
        rv(0) := 0;
      end if;
    end if;
    if yc > 1
    then
      ly := y;
      if y( yc - 1 ) < cm2
      then
        sf := trunc( cm / ( y( yc - 1 ) + 1 ) );
        r := 0;
        for i in 0 .. xc - 1
        loop
          tmp := x(i) * sf + r;
          if tmp < cm
          then
            r := 0;
            rv(i) := tmp;
          else
            r := trunc( tmp * cmi );
            rv(i) := tmp - r * cm;
          end if;
        end loop;
        if r > 0
        then
          rv(xc) := r;
          xc := xc + 1;
        end if;
        --
        r := 0;
        for i in 0 .. yc - 1
        loop
          tmp := ly(i) * sf + r;
          if tmp < cm
          then
            r := 0;
            ly(i) := tmp;
          else
            r := trunc( tmp * cmi );
            ly(i) := tmp - r * cm;
          end if;
        end loop;
      else
        rv := x;
      end if;
      if xc = 2
      then
        rv(2) := 0;
        xc := 3;
      end if;
      --
      if ge( rv, ly, xc - yc )
      then
        sub( rv, ly, xc - yc );
      end if;
      --
      d2 := ly( yc - 1 ) * cm + ly( yc - 2 );
      for i in reverse yc .. xc - 1
      loop
        if rv(i) > 0
        then
          if rv(i) > d2
          then
            d := cm - 1;
          else
            tmp := rv(i) * cm + rv( i - 1 );
            if tmp > d2
            then
              d := cm - 1;
            else
              d := least( trunc( cm * ( tmp / d2 ) + rv( i - 2 ) / d2 ), cm - 1 );
            end if;
          end if;
          dq.delete;
          r := 0;
          for j in 0 .. yc - 1
          loop
            tmp := ly(j) * d + r;
            if tmp < cm
            then
              r := 0;
              dq(j) := tmp;
            else
              r := trunc( tmp * cmi );
              dq(j) := tmp - r * cm;
            end if;
          end loop;
          dq( yc ) := r;
          if not ge( rv, dq, i - yc )
          then
            r := 0;
            for j in 0 .. yc - 1
            loop
              tmp := dq(j);
              tmp := tmp - ly(j) - r;
              if dq(j) < 0
              then
                dq(j) := tmp + cm;
                r := 1;
              else
                dq(j) := tmp;
                r := 0;
              end if;
            end loop;
            if r > 0
            then
              dq(yc) := dq(yc) - 1;
            end if;
          end if;
          sub( rv, dq, i - yc );
        end if;
      end loop;
      --
      --   if rv >= ly then substract ly from rv
      if ge( rv, ly, 0 )
      then
        sub( rv, ly, 0 );
      end if;
      --
      for i in reverse 1 .. xc - 1
      loop
        exit when rv(i) > 0;
        rv.delete(i);
      end loop;
    --
    else
      d := y(0);
      r := 0;
      if d > 1
      then
        for i in reverse 0 .. x.count - 1
        loop
          tmp := r * cm + x(i);
          r := tmp - trunc( tmp / d ) * d;
        end loop;
      end if;
      rv(0) := r;
    end if;
    if sf is not null
    then
      r := 0;
      for i in reverse 0 .. rv.count - 1
      loop
        tmp := rv(i) + r * cm;
        rv(i) := trunc( tmp / sf );
        r := tmp - rv(i) * sf;
      end loop;
      tmp := rv.count - 1;
      if tmp > 0 and rv( tmp ) = 0
      then
        rv.delete( tmp );
      end if;
    end if;
    return rv;
  end;
  --
  function addmod( p1 tp_mag, p2 tp_mag, m tp_mag )
  return tp_mag
  is
    rv tp_mag := radd( p1, p2 );
  begin
    if r_greater_equal( rv, m )
    then
      rv := rsub( rv, m );
    end if;
    return rv;
  end;
  --
  function submod( p1 tp_mag, p2 tp_mag, m tp_mag )
  return tp_mag
  is
    rv tp_mag := radd( p1, rsub( m, p2 ) );
  begin
    if r_greater_equal( rv, m )
    then
      rv := rsub( rv, m );
    end if;
    return rv;
  end;
  --
  function mulmod( p1 tp_mag, p2 tp_mag, m tp_mag )
  return tp_mag
  is
  begin
    return xmod( rmul( p1, p2 ), m );
  end;
  --
  function small_nmulmod( p1 tp_mag, n number, m tp_mag )
  return tp_mag
  is
    rv tp_mag := nmul( p1, n );
  begin
    for i in 1 .. 5  -- expect n < 5
    loop
      exit when not r_greater_equal( rv, m );
      if i = 5
      then
        rv := xmod( rv, m );
      else
        rv := rsub( rv, m );
      end if;
    end loop;
    return rv;
  end;
  --
  function rdiv2( p1 tp_mag )
  return tp_mag
  is
    c number;
    t number;
    rv tp_mag;
  begin
    if p1.count = 1
    then
      rv(0) := trunc( p1( 0 ) / 2 );
    else
      c := 0;
      for i in reverse 0 .. p1.count - 1
      loop
        t := p1( i ) + c;
        rv( i ) := trunc( t / 2 );
        c :=  case when bitand( t, 1 ) = 1 then cm else 0 end;
      end loop;
      while rv( rv.last ) = 0
      loop
        rv.delete( rv.last );
      end loop;
    end if;
    return rv;
  end;
  --
  function powmod( pa tp_mag, pb tp_mag, pm tp_mag )
  return tp_mag
  is
    m1 tp_mag;
    r tp_mag;
    k pls_integer;
    mc pls_integer;
    ninv0 number;
    bx0 number;
    mx0 number;
    nx number;
    xx number;
    xm tp_mag;
    am tp_mag;
    one tp_mag;
    tx varchar2(3999);
    sb varchar2(3999);
    nr number;
    hb boolean := false;
    function monpro( pa tp_mag, pb tp_mag )
    return tp_mag
    is
      b number;
      c number;
      m number;
      tmp number;
      t0 number;
      t tp_mag;
      ta tp_mag;
      tb tp_mag;
    begin
      ta := pa;
      for i in ta.count .. mc - 1
      loop
        ta( i ) := 0;
      end loop;
      tb := pb;
      for i in tb.count .. mc - 1
      loop
        tb( i ) := 0;
      end loop;
      for i in 0 .. mc
      loop
        t( i ) := 0;
      end loop;
      for i in 0 .. mc - 1
      loop
        t( mc + 1 ) := 0;
        tmp := t(0) + ta(0) * tb( i );
        c := trunc( tmp * cmi );
        t0 := tmp - c * cm;
        t(1) := t(1) + c;
        tmp := t0 * ninv0;
        m := tmp - trunc( tmp * cmi ) * cm;
        tmp := t0 + m * m1(0);
        if tmp >= cm
        then
          t(1) := t(1) + trunc( tmp * cmi );
        end if;
        -- check for overflow of t(1)?
        for j in 1 .. mc - 1
        loop
          tmp := t( j ) + ta( j ) * tb( i ) + m * m1( j );
          if tmp >= cm
          then
            c := trunc( tmp * cmi );
            t( j - 1 ) := tmp - c * cm;
            if c >= cm
            then
              c := c - cm;
              t( j + 2 ) := t( j + 2 ) + 1;
            end if;
            t( j + 1 ) := t( j + 1 ) + c;
          else
            t( j - 1 ) := tmp;
          end if;
        end loop;
        t( mc - 1 ) := t( mc );
        t( mc ) := t( mc + 1 );
      end loop;
      t.delete(mc+1);
      for j in reverse 1 .. t.count - 1
      loop
        exit when t(j) > 0;
        t.delete(j);
      end loop;
      b := t.count - mc;
      if b = 0
      then
        for i in reverse 0 .. mc - 1
        loop
          b := t(i) - m1(i);
          exit when b != 0;
        end loop;
        if b = 0
        then
          t.delete;
          t(0) := 0;
        end if;
      end if;
      if b > 0
      then
        b := 0;
        for i in 0 .. mc - 1
        loop
          tmp := t(i) - m1(i) - b;
          if tmp < 0
          then
            b := 1;
            t(i) := tmp + cm;
          else
            b := 0;
            t(i) := tmp;
          end if;
        end loop;
        for i in mc .. t.count - 1
        loop
          tmp := t(i) - b;
          if tmp < 0
          then
            b := 1;
            t(i) := tmp + cm;
          else
            t(i) := tmp;
            exit;
          end if;
        end loop;
        for j in reverse 1 .. t.count - 1
        loop
          exit when t(j) > 0;
          t.delete(j);
        end loop;
      end if;
      return t;
    end;
  begin
    m1 := pm;
    mc := m1.count;
    k := mc * ccc * 4;
    for i in 0 .. mc - 1
    loop
      r( i ) := 0;
    end loop;
    r( mc ) := 1;
    -- See "A New Algorithm for Inversion mod pk", Cetin Kaya Koc, https://eprint.iacr.org/2017/411.pdf
    bx0 := m1(0);
    mx0 := 2 * bx0;
    if mx0 >= cm
    then
      mx0 := mx0 - cm;
    end if;
    nx := 1;
    for j in 1 .. ccc * 4 - 1
    loop
      xx := bitand( bx0, power( 2, j ) );
      if xx > 0
      then
        nx := nx + xx;
        bx0 := bx0 + mx0;
        if bx0 >= cm
        then
          bx0 := bx0 - cm;
        end if;
      end if;
      mx0 := 2 * mx0;
      if mx0 >= cm
      then
        mx0 := mx0 - cm;
      end if;
    end loop;
    ninv0 := cm - nx;
    --
    xm := xmod( r, m1 );
    am := xmod( rmul( pa, xm ), m1 );
    sb := nvl( ltrim( demag( pb ), '0' ), '0' );
    for i in 1 .. length( sb )
    loop
      nr := to_number( substr( sb, i, 1 ), 'x' );
      for j in reverse 0 .. 3
      loop
        if not hb and bitand( nr, power( 2, j ) ) > 0
        then
          hb := true;
        end if;
        if hb
        then
          xm := monpro( xm, xm );
        end if;
        if bitand( nr, power( 2, j ) ) > 0
        then
          xm := monpro( am, xm );
        end if;
      end loop;
    end loop;
    one(0) := 1;
    return monpro( xm, one);
  end;
  --
  function powmod( pa varchar2, pb varchar2, pm varchar2 )
  return varchar2
  is
  begin
    return demag( powmod( mag( pa ), mag( pb ), mag( pm ) ) );
  end;
  --
  procedure get_named_ed_curve( p_name in varchar2, p_curve out tp_ed_curve )
  is
  begin
    if p_name in ( 'ed25519', 'ssh-ed25519' )
    then
      p_curve.nlen := 32;  -- b / 8
      p_curve.l := mag( '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed' );   -- prime order 2^252 + 27742317777372353535851937790883648493
      p_curve.d := mag( '52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3' );   -- -121665/121666 = 37095705934669439343138083508754565189542113879843219016388785533085940283555
      p_curve.q := mag( '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed' );   -- 2^255 - 19  (mod 2^256)
      p_curve.i := mag( '2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0' );   -- sqrt(-1) mod q
      p_curve.b.x := mag( '216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A' ); -- 15112221349535400772501151409588531511454012693041857206046113283949847762202
      p_curve.b.y := mag( '6666666666666666666666666666666666666666666666666666666666666658' ); -- 46316835694926478169428394003475163141307993866256225615783033603165251855960
      p_curve.b.z := c_mag_1;
      p_curve.b.t := mag( '67875F0FD78B766566EA4E8E64ABE37D20F09F80775152F56DDE8AB3A5B7DDA3' );
    end if;
  end;
  --
  procedure get_named_curve( p_name in varchar2, p_curve out tp_ec_curve )
  is
  begin
    if p_name = 'nistp256'
    then
      p_curve.nlen := 32;
      p_curve.prime          := mag( 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff' );
      p_curve.group_order    := mag( 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551' );
      p_curve.a              := mag( 'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc' );
      p_curve.b              := mag( '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b' );
      p_curve.generator.x    := mag( '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296' );
      p_curve.generator.y    := mag( '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5' );
      p_curve.p_plus_1_div_4 := mag( '3fffffffc0000000400000000000000000000000400000000000000000000000' );
    elsif p_name = 'nistp384'
    then
      p_curve.nlen := 48;
      p_curve.prime          := mag( 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff' );
      p_curve.group_order    := mag( 'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973' );
      p_curve.a              := mag( 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc' );
      p_curve.b              := mag( 'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef' );
      p_curve.generator.x    := mag( 'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7' );
      p_curve.generator.y    := mag( '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f' );
      p_curve.p_plus_1_div_4 := mag( '3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffc00000000000000040000000' );
    elsif p_name = 'nistp521'
    then
      p_curve.nlen := 66;
      p_curve.prime          := mag( '1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' );
      p_curve.group_order    := mag( '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409' );
      p_curve.a              := mag( '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc' );
      p_curve.b              := mag( '51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00' );
      p_curve.generator.x    := mag( 'c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66' );
      p_curve.generator.y    := mag( '11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650' );
      p_curve.p_plus_1_div_4 := mag( '8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' );
    end if;
  end;
  --
  procedure bytes_to_ec_point( p_bytes raw, p_curve tp_ec_curve, p_point out tp_ec_point )
  is
    l_first varchar2(2);
    l_y2 tp_mag;
  begin
    l_first := utl_raw.substr( p_bytes, 1, 1 );
    if not (  ( l_first = '04' and utl_raw.length( p_bytes ) = 1 + 2 * p_curve.nlen )
           or ( l_first in ( '02', '03' ) and utl_raw.length( p_bytes ) = 1 + p_curve.nlen )
           )
    then
      raise_application_error( -20024, 'invalid encoded EC point.' );
    end if;
    if l_first = '04'
    then
      p_point.x := mag( utl_raw.substr( p_bytes, 2, p_curve.nlen ) );
      p_point.y := mag( utl_raw.substr( p_bytes, 2 + p_curve.nlen, p_curve.nlen ) );
      -- check if it's a point on the curve
      if not requal( addmod( addmod( powmod( p_point.x, mag( '3' ), p_curve.prime )
                                   , mulmod( p_point.x, p_curve.a, p_curve.prime )
                                   , p_curve.prime
                                   )
                           , p_curve.b
                           , p_curve.prime
                           )
                   , mulmod( p_point.y, p_point.y, p_curve.prime )
                   )
      then
        raise_application_error( -20025, 'EC Point is not on EC Curve.' );
      end if;
    else
      -- see https://tools.ietf.org/id/draft-jivsov-ecc-compact-05.html
      p_point.x := mag( utl_raw.substr( p_bytes, 2, p_curve.nlen ) );
      l_y2 := addmod( addmod( powmod( p_point.x, mag( '3' ), p_curve.prime )
                            , mulmod( p_point.x, p_curve.a, p_curve.prime )
                            , p_curve.prime
                            )
                    , p_curve.b
                    , p_curve.prime
                    );
      if l_first = '02'
      then
        p_point.y := powmod( l_y2, p_curve.p_plus_1_div_4, p_curve.prime );
      else
        p_point.y := rsub( p_curve.prime, powmod( l_y2, p_curve.p_plus_1_div_4, p_curve.prime ) );
      end if;
      -- raise_application_error( -20023, 'EC Point compression not supported.' );
    end if;
  end;
  --
  function from_jacobian( p_point tp_ec_point, p_curve tp_ec_curve )
  return tp_ec_point
  is
    l_inv tp_mag;
    l_tmp tp_mag;
    l_rv tp_ec_point;
  begin
    if p_point.z(0) = 1 and p_point.z.count = 1
    then
      l_rv.x := p_point.x;
      l_rv.y := p_point.y;
    elsif p_point.y(0) = 0 and p_point.y.count = 1
    then -- infinity
      l_rv.x := c_mag_0;
      l_rv.y := c_mag_0;
    else
      l_inv := powmod( p_point.z, nsub( p_curve.prime, 2 ), p_curve.prime );
      l_tmp := mulmod( l_inv, l_inv, p_curve.prime );
      l_rv.x := mulmod( p_point.x, l_tmp, p_curve.prime );
      l_rv.y := mulmod( p_point.y, mulmod( l_tmp, l_inv, p_curve.prime ), p_curve.prime );
    end if;
    return l_rv;
  end;
  --
  function to_jacobian( p_point tp_ec_point )
  return tp_ec_point
  is
    l_rv tp_ec_point;
  begin
    l_rv.x := p_point.x;
    l_rv.y := p_point.y;
    l_rv.z := mag( '1' );
    return l_rv;
  end;
  --
  function double_jpoint( p tp_ec_point, c tp_ec_curve )
  return tp_ec_point
  is
    l_ysqr tp_mag;
    l_z4 tp_mag;
    l_s tp_mag;
    l_m tp_mag;
    l_rv tp_ec_point;
    c_mag_4 tp_mag := mag( '4' );
  begin
    if p.y(0) = 0 and p.y.count = 1
    then -- infinity
      l_rv.x := c_mag_0;
      l_rv.y := c_mag_0;
      l_rv.z := c_mag_0;
    else
      l_ysqr := mulmod( p.y, p.y, c.prime );
      l_z4 := powmod( p.z, c_mag_4, c.prime );
      l_s := mulmod( small_nmulmod( p.x, 4, c.prime ), l_ysqr, c.prime );
      l_m := addmod( small_nmulmod( mulmod( p.x, p.x, c.prime )
                                  , 3
                                  , c.prime
                                  )
                   , mulmod( c.a, l_z4, c.prime )
                   , c.prime
                   );
      l_rv.x := submod( mulmod( l_m, l_m, c.prime )
                      , small_nmulmod( l_s, 2, c.prime )
                      , c.prime
                      );
      l_rv.y := submod( mulmod( l_m, submod( l_s, l_rv.x, c.prime ), c.prime )
                      , small_nmulmod( mulmod( l_ysqr, l_ysqr, c.prime ), 8, c.prime )
                      , c.prime
                      );
      l_rv.z := mulmod( small_nmulmod( p.y, 2, c.prime ), p.z, c.prime );
    end if;
    return l_rv;
  end;
  --
  function add_jpoint( p1 tp_ec_point, p2 tp_ec_point, c tp_ec_curve )
  return tp_ec_point
  is
    l_p1z_pwr2 tp_mag;
    l_p2z_pwr2 tp_mag;
    l_u1 tp_mag;
    l_u2 tp_mag;
    l_s1 tp_mag;
    l_s2 tp_mag;
    l_h tp_mag;
    l_h2 tp_mag;
    l_h3 tp_mag;
    l_r tp_mag;
    l_u1h2 tp_mag;
    l_rv tp_ec_point;
  begin
    if p1.y(0) = 0 and p1.y.count = 1
    then -- infinity
      return p2;
    end if;
    if p2.y(0) = 0 and p2.y.count = 1
    then -- infinity
      return p1;
    end if;
    l_p1z_pwr2 := mulmod( p1.z, p1.z, c.prime );
    l_p2z_pwr2 := mulmod( p2.z, p2.z, c.prime );
    l_u1 := mulmod( p1.x, l_p2z_pwr2, c.prime );
    l_u2 := mulmod( p2.x, l_p1z_pwr2, c.prime );
    l_s1 := mulmod( p1.y, mulmod( l_p2z_pwr2, p2.z, c.prime ), c.prime );
    l_s2 := mulmod( p2.y, mulmod( l_p1z_pwr2, p1.z, c.prime ), c.prime );
    if requal( l_u1, l_u2 )
    then
       if requal( l_s1, l_s2 )
       then
         l_rv := double_jpoint( p1, c );
       else
         l_rv.x := c_mag_0; -- infinity
         l_rv.y := c_mag_0;
         l_rv.z := c_mag_0;
       end if;
    else
      l_h := submod( l_u2, l_u1, c.prime );
      l_r := submod( l_s2, l_s1, c.prime );
      l_h2 := mulmod( l_h, l_h, c.prime );
      l_h3 := mulmod( l_h2, l_h, c.prime );
      l_u1h2 := mulmod( l_h2, l_u1, c.prime );
      l_rv.x := submod( submod( mulmod( l_r, l_r, c.prime ), l_h3, c.prime )
                      , small_nmulmod( l_u1h2, 2, c.prime )
                      , c.prime
                      );
      l_rv.y := submod( mulmod( l_r, submod( l_u1h2, l_rv.x, c.prime ), c.prime )
                      , mulmod( l_s1, l_h3, c.prime )
                      , c.prime
                      );
      l_rv.z := mulmod( l_h, mulmod( p1.z, p2.z, c.prime ), c.prime );
    end if;
    return l_rv;
  end;
  --
  function multiply_jpoint( p tp_ec_point, m tp_mag, c tp_ec_curve )
  return tp_ec_point
  is
    l_rv tp_ec_point;
  begin
    if p.y(0) = 0 and p.y.count = 1
    then -- infinity
      l_rv.x := c_mag_0;
      l_rv.y := c_mag_0;
      l_rv.z := c_mag_0;
    elsif m(0) = 1 and m.count = 1
    then
      l_rv := p;
    elsif r_greater_equal( m, c.group_order )
    then
      l_rv := multiply_jpoint( p, xmod( m, c.group_order ), c );
    elsif bitand( m(0), 1 ) = 0
    then
      l_rv := double_jpoint( multiply_jpoint( p, rdiv2( m ), c ), c );
    else
      l_rv := add_jpoint( double_jpoint( multiply_jpoint( p, rdiv2( m ), c ), c ), p, c );
    end if;
    return l_rv;
  end;
  --
  function add_point( pa tp_ec_point, pb tp_ec_point, pc tp_ec_curve )
  return tp_ec_point
  is
  begin
    return from_jacobian( add_jpoint( to_jacobian( pa ), to_jacobian( pb ), pc ), pc );
  end;
  --
  function multiply_point( pa tp_ec_point, pm tp_mag, pc tp_ec_curve )
  return tp_ec_point
  is
  begin
    return from_jacobian( multiply_jpoint( to_jacobian( pa ), pm, pc ), pc );
  end;
  --
  procedure init_hmac_ids
  is
  begin
    execute immediate 'begin :x := dbms_crypto.HMAC_MD5; end;'   using out HMAC_MD5;
    execute immediate 'begin :x := dbms_crypto.HMAC_SH1; end;'   using out HMAC_SH1;
    execute immediate 'begin :x := dbms_crypto.HASH_MD5; end;'   using out HASH_MD5;
    execute immediate 'begin :x := dbms_crypto.HASH_SH1; end;'   using out HASH_SH1;
    execute immediate 'begin :x := dbms_crypto.HMAC_SH256; end;' using out HMAC_SH256;
    execute immediate 'begin :x := dbms_crypto.HMAC_SH384; end;' using out HMAC_SH384;
    execute immediate 'begin :x := dbms_crypto.HMAC_SH512; end;' using out HMAC_SH512;
    execute immediate 'begin :x := dbms_crypto.HASH_SH256; end;' using out HASH_SH256;
    execute immediate 'begin :x := dbms_crypto.HASH_SH384; end;' using out HASH_SH384;
    execute immediate 'begin :x := dbms_crypto.HASH_SH512; end;' using out HASH_SH512;
  exception when others then null;
  end;
  --
  procedure write_packet( p_buf raw )
  is
    l_dummy pls_integer;
    l_packet_len pls_integer;
    l_padding_len pls_integer;
    l_block_size pls_integer;
    l_buf raw(32767);
    l_encr raw(32767);
    l_mac raw(100);
    l_hash_type pls_integer;
  begin
    if g_encr_algo_c in ( 'aes128-cbc', 'aes128-ctr', 'aes192-cbc', 'aes192-ctr', 'aes256-cbc', 'aes256-ctr', 'rijndael256-cbc', 'rijndael-cbc@lysator.liu.se' )
    then
      l_block_size := 16;
    else
      l_block_size := 8;
    end if;
    l_packet_len := utl_raw.length( p_buf );
    l_padding_len := 4;-- size of package length
    l_padding_len := l_block_size
                   - mod( 4 -- size of package length
                        + 1 -- size of padding length
                        + l_packet_len -- size of payload
                        + l_padding_len
                        , l_block_size
                        ) + l_padding_len;
    l_packet_len := l_packet_len + l_padding_len + 1;
    l_buf := utl_raw.concat( to_char( l_packet_len, 'fm0XXXXXXX' )
                           , to_char( l_padding_len, 'fm0X' )
                           , p_buf
                           , dbms_crypto.randombytes( l_padding_len )
                           );
    if g_mac_algo_c in ( 'hmac-sha1', 'hmac-sha1-96' )
    then
      l_hash_type := HMAC_SH1;
    elsif g_mac_algo_c in ( 'hmac-md5', 'hmac-md5-96' )
    then
      l_hash_type := HMAC_MD5;
    elsif g_mac_algo_c in ( 'hmac-sha2-256' )
    then
      l_hash_type := HMAC_SH256;
    elsif g_mac_algo_c in ( 'hmac-sha2-512' )
    then
      l_hash_type := HMAC_SH512;
    end if;
    if l_hash_type is not null
    then
      l_mac := dbms_crypto.mac( utl_raw.concat( to_char( g_seqn_c, 'fm0XXXXXXX' ), l_buf )
                              , l_hash_type
                              , g_key_mac_c2s
                              );
      if g_mac_algo_c in ( 'hmac-md5-96', 'hmac-sha1-96' )
      then
        l_mac := utl_raw.substr( l_mac, 1, 12 );
      end if;
    end if;
    if g_encr_algo_c in ( 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'rijndael256-cbc', 'rijndael-cbc@lysator.liu.se' )
    then
      l_buf := dbms_crypto.encrypt( l_buf
                                  , dbms_crypto.ENCRYPT_AES + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_NONE
                                  , g_key_cypher_c2s
                                  , g_iv_cypher_c2s
                                  );
      g_iv_cypher_c2s := utl_raw.substr( l_buf, - l_block_size );
    elsif g_encr_algo_c = '3des-cbc'
    then
      l_buf := dbms_crypto.encrypt( l_buf
                                  , dbms_crypto.ENCRYPT_3DES + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_NONE
                                  , g_key_cypher_c2s
                                  , g_iv_cypher_c2s
                                  );
      g_iv_cypher_c2s := utl_raw.substr( l_buf, - l_block_size );
    elsif g_encr_algo_c in ( 'aes128-ctr', 'aes192-ctr', 'aes256-ctr' )
    then
      for i in 0 .. trunc( l_packet_len / l_block_size )
      loop
        l_encr := utl_raw.concat( l_encr
                                , utl_raw.bit_xor( utl_raw.substr( l_buf, i * l_block_size + 1, l_block_size )
                                                 , dbms_crypto.encrypt( g_iv_cypher_c2s
                                                                      , dbms_crypto.ENCRYPT_AES + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_NONE
                                                                      , g_key_cypher_c2s
                                                                      )
                                                 )
                                );
        g_iv_cypher_c2s := to_char( nvl( to_number( nullif( g_iv_cypher_c2s
                                                          , rpad( 'F', 32, 'F' )
                                                          )
                                                  , rpad( 'X', 32, 'X' )
                                                  ) + 1
                                       , 0
                                       )
                                  , 'FM' || rpad( '0', 32, 'X' )
                                  );
      end loop;
      l_buf := l_encr;
    end if;
    l_dummy := utl_tcp.write_raw( c => g_con, data => l_buf );
    if g_mac_algo_c is not null
    then
      l_dummy := utl_tcp.write_raw( c => g_con, data => l_mac );
    end if;
    g_seqn_c := g_seqn_c + 1;
    if g_seqn_c >= 4294967296
    then
      g_seqn_c := 0;
    end if;
  end;
  --
  function decrypt( p_encr raw )
  return raw
  is
    l_tmp raw(256);
    l_type pls_integer;
  begin
    if g_encr_algo_s is null or g_encr_algo_s = 'none'
    then
      return p_encr;
    elsif g_encr_algo_s in ( 'aes128-ctr', 'aes192-ctr', 'aes256-ctr' )
    then
      l_tmp := dbms_crypto.encrypt( substr( to_char( g_iv_cypher_s2c_ctr, 'FM0XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' ), -32 )
                                  , dbms_crypto.ENCRYPT_AES + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_NONE
                                  , g_key_cypher_s2c
                                  );
      g_iv_cypher_s2c_ctr := g_iv_cypher_s2c_ctr + 1;
      if g_iv_cypher_s2c_ctr > 340282366920938463463374607431768211455
      then
        g_iv_cypher_s2c_ctr := 0;
      end if;
      return utl_raw.bit_xor( l_tmp, p_encr );
    end if;
    if g_encr_algo_s in ( 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'rijndael256-cbc', 'rijndael-cbc@lysator.liu.se' )
    then
      l_type := dbms_crypto.ENCRYPT_AES + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_NONE;
    elsif g_encr_algo_s = '3des-cbc'
    then
      l_type := dbms_crypto.ENCRYPT_3DES + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_NONE;
    end if;
    l_tmp := dbms_crypto.decrypt( p_encr
                                , l_type
                                , g_key_cypher_s2c
                                , g_iv_cypher_s2c
                                );
    g_iv_cypher_s2c := p_encr;
    return l_tmp;
  end;
  --
  function read_packet
  return raw
  is
    l_packet_len pls_integer;
    l_padding_len pls_integer;
    l_payload_len pls_integer;
    l_cur_len pls_integer;
    l_buf raw(32767);
    l_vbuf varchar2(32767);
    l_padding raw(256);
    l_mac raw(256);
    l_tmp raw(256);
    l_block_size pls_integer;
  begin
    if g_encr_algo_s in ( 'aes128-cbc', 'aes128-ctr', 'aes192-cbc', 'aes192-ctr', 'aes256-cbc', 'aes256-ctr', 'rijndael256-cbc', 'rijndael-cbc@lysator.liu.se' )
    then
      l_block_size := 16;
    else
      l_block_size := 8;
    end if;
    l_tmp := decrypt( utl_tcp.get_raw( g_con, l_block_size ) );
    l_packet_len := to_number( utl_raw.substr( l_tmp, 1, 4 ), 'XXXXXXXX' );
    l_padding_len := to_number( utl_raw.substr( l_tmp, 5, 1 ), 'XX' );
    l_payload_len := l_packet_len - l_padding_len - 1;
    l_vbuf := utl_raw.substr( l_tmp, 6 );
    for i in 2 .. ( 4 + l_packet_len ) / l_block_size
    loop
      l_tmp := decrypt( utl_tcp.get_raw( g_con, l_block_size ) );
      l_vbuf := l_vbuf || l_tmp;
      if length( l_vbuf ) >= 32734  -- 32766 - 2 * (max blocksize)
      then
        if l_buf is null
        then
          l_buf := hextoraw( substr( l_vbuf, 1, 2 * l_payload_len ) );
        else
          l_buf := utl_raw.concat( l_buf, hextoraw( substr( l_vbuf, 1, 2 * ( l_payload_len - utl_raw.length( l_buf ) ) ) ) );
        end if;
        l_vbuf := null;
      end if;
    end loop;
    if l_vbuf is not null
    then
      if l_buf is null
      then
        l_buf := hextoraw( substr( l_vbuf, 1, 2 * l_payload_len ) );
      else
        l_buf := utl_raw.concat( l_buf, hextoraw( substr( l_vbuf, 1, 2 * ( l_payload_len - utl_raw.length( l_buf ) ) ) ) );
      end if;
    end if;
    g_seqn_s := g_seqn_s + 1;
    if g_seqn_s >= 4294967296
    then
      g_seqn_s := 0;
    end if;
    if g_mac_algo_s in ( 'hmac-sha1', 'hmac-ripemd160' )
    then
      l_mac := utl_tcp.get_raw( g_con, 20 );
    elsif g_mac_algo_s = 'hmac-md5'
    then
      l_mac := utl_tcp.get_raw( g_con, 16 );
    elsif g_mac_algo_s = 'hmac-sha2-256'
    then
      l_mac := utl_tcp.get_raw( g_con, 32 );
    elsif g_mac_algo_s = 'hmac-sha2-512'
    then
      l_mac := utl_tcp.get_raw( g_con, 64 );
    elsif g_mac_algo_s in ( 'hmac-md5-96', 'hmac-sha1-96' )
    then
      l_mac := utl_tcp.get_raw( g_con, 12 );
    end if;
    -- check mac?
    return l_buf;
  end;
  --
  procedure get_string( p_idx in out pls_integer, p_buf raw, p_dest out raw )
  is
    l_len pls_integer;
  begin
    l_len := to_number( rawtohex( utl_raw.substr( p_buf, p_idx, 4 ) ), 'XXXXXXXX' );
    if l_len > 0
    then
      p_dest := utl_raw.substr( p_buf, p_idx + 4, l_len );
    else
      p_dest := null;
    end if;
    p_idx := p_idx + 4 + l_len;
  end;
--
  procedure get_int32( p_idx in out pls_integer, p_buf raw, p_dest out number )
  is
  begin
    p_dest := to_number( rawtohex( utl_raw.substr( p_buf, p_idx, 4 ) ), 'XXXXXXXX' );
    p_idx := p_idx + 4;
  end;
--
  procedure get_int64( p_idx in out pls_integer, p_buf raw, p_dest out number )
  is
  begin
    p_dest := to_number( rawtohex( utl_raw.substr( p_buf, p_idx, 8 ) ), 'XXXXXXXXXXXXXXXX' );
    p_idx := p_idx + 8;
  end;
--
  procedure get_mpint( p_idx in out pls_integer, p_buf raw, p_dest out raw )
  is
  begin
    get_string( p_idx, p_buf, p_dest );
  end;
--
  function read_name_list( p_idx in out pls_integer, p_buf raw )
  return tp_name_list
  is
    l_len pls_integer;
    l_pos pls_integer;
    l_tmp varchar2(32767);
    l_name_list tp_name_list := tp_name_list();
  begin
    l_len := to_number( utl_raw.substr( p_buf, p_idx, 4 ), 'XXXXXXXX' );
    if l_len > 0
    then
      l_tmp := utl_raw.cast_to_varchar2( utl_raw.substr( p_buf, p_idx + 4, l_len ) );
      loop
        l_pos := instr( l_tmp, ',' );
        exit when l_pos = 0;
        l_name_list.extend;
        l_name_list( l_name_list.count ) := substr( l_tmp, 1, l_pos - 1 );
        l_tmp := substr( l_tmp, l_pos + 1 );
      end loop;
      l_name_list.extend;
      l_name_list( l_name_list.count ) := l_tmp;
    end if;
    p_idx := p_idx + 4 + l_len;
    return l_name_list;
  end;
  --
  procedure append_byte( p_buf in out nocopy raw, p_val raw )
  is
  begin
    p_buf := utl_raw.concat( p_buf, p_val );
  end;
  --
  procedure append_boolean( p_buf in out nocopy raw, p_val boolean )
  is
  begin
    p_buf := utl_raw.concat( p_buf, case when p_val then '01' else '00' end );
  end;
  --
  procedure append_int32( p_buf in out nocopy raw, p_val number )
  is
  begin
    p_buf := utl_raw.concat( p_buf
                           , to_char( nvl( p_val, 0 )
                                    , 'fm0XXXXXXX'
                                    )
                           );
  end;
--
  procedure append_int64( p_buf in out nocopy raw, p_val number )
  is
  begin
    p_buf := utl_raw.concat( p_buf
                           , to_char( nvl( p_val, 0 )
                                    , 'fm0XXXXXXXXXXXXXXX'
                                    )
                           );
  end;
  --
  procedure append_string( p_buf in out nocopy raw, p_string raw )
  is
  begin
    p_buf := utl_raw.concat( p_buf
                           , to_char( nvl( utl_raw.length( p_string ), 0 )
                                    , 'fm0XXXXXXX'
                                    )
                           , p_string
                           );
  end;
  --
  procedure append_mpint( p_buf in out nocopy raw, p_mpint raw, p_bytes pls_integer := null )
  is
    c_80 constant raw(1) := hextoraw( '80' );
  begin
    if p_bytes is not null and utl_raw.length( p_mpint ) < p_bytes
    then
      append_string( p_buf
                   , utl_raw.concat( utl_raw.copies( '00', p_bytes - utl_raw.length( p_mpint ) )
                                   , p_mpint
                                   )
                   );
    else
      if utl_raw.bit_and( utl_raw.substr( p_mpint, 1, 1 ), c_80 ) = c_80
      then
        append_string( p_buf, utl_raw.concat( '00', p_mpint ) );
      else
        append_string( p_buf, p_mpint );
      end if;
    end if;
  end;
  --
  procedure append_name_list( p_buf in out nocopy raw, p_name_list tp_name_list )
  is
    l_tmp varchar2(32767);
  begin
    if p_name_list is null or p_name_list.count = 0
    then
      p_buf := utl_raw.concat( p_buf, '00000000' );
      return;
    end if;
    for i in p_name_list.first .. p_name_list.last
    loop
      l_tmp := l_tmp || ','  || p_name_list( i );
    end loop;
    l_tmp := substr( l_tmp, 2 );
    p_buf := utl_raw.concat( p_buf
                           , to_char( length( l_tmp ), 'fm0XXXXXXX' )
                           , utl_i18n.string_to_raw( l_tmp, 'US7ASCII' )
                           );
  end;
  --
  procedure handle_kex( p_buf raw, p_fingerprint varchar2 := null, p_trust boolean := null );
  --
  procedure show_disconnect_msg( p_buf raw )
  is
    l_reason number;
    l_idx number;
    l_buf raw(32767);
  begin
    if utl_raw.substr( p_buf, 1, 1 ) = SSH_MSG_DISCONNECT
    then
      l_idx := 2;
      get_int32( l_idx, p_buf, l_reason );
      info_msg( 'reason: ' || l_reason || ', '
              || case l_reason
                   when 1  then 'SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT'
                   when 2  then 'SSH_DISCONNECT_PROTOCOL_ERROR'
                   when 3  then 'SSH_DISCONNECT_KEY_EXCHANGE_FAILED'
                   when 4  then 'SSH_DISCONNECT_RESERVED'
                   when 5  then 'SSH_DISCONNECT_MAC_ERROR'
                   when 6  then 'SSH_DISCONNECT_COMPRESSION_ERROR'
                   when 7  then 'SSH_DISCONNECT_SERVICE_NOT_AVAILABLE'
                   when 8  then 'SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED'
                   when 9  then 'SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE'
                   when 10 then 'SSH_DISCONNECT_CONNECTION_LOST'
                   when 11 then 'SSH_DISCONNECT_BY_APPLICATION'
                   when 12 then 'SSH_DISCONNECT_TOO_MANY_CONNECTIONS'
                   when 13 then 'SSH_DISCONNECT_AUTH_CANCELLED_BY_USER'
                   when 14 then 'SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE'
                   when 15 then 'SSH_DISCONNECT_ILLEGAL_USER_NAME'
                  end
              );
      get_string( l_idx, p_buf, l_buf );
      if l_buf is not null
      then
        info_msg( utl_i18n.raw_to_char( l_buf, 'AL32UTF8' ) );
      end if;
      get_string( l_idx, p_buf, l_buf );
      if l_buf is not null
      then
        info_msg( utl_i18n.raw_to_char( l_buf, 'AL32UTF8' ) );
      end if;
    end if;
  end;
  --
  procedure read_until( p_buf in out raw, p_msg1 raw, p_msg2 raw := null, p_msg3 raw := null )
  is
    l_idx pls_integer;
    l_buf raw(32767);
  begin
    loop
      p_buf := read_packet;
      case utl_raw.substr( p_buf, 1, 1 )
        when p_msg1
        then
          exit;
        when p_msg2
        then
          exit;
        when p_msg3
        then
          exit;
        when SSH_MSG_DISCONNECT
        then
          show_disconnect_msg( p_buf );
          raise_application_error( -20020, 'Disconnected by server' );
        when SSH_MSG_IGNORE
        then
          null;
        when SSH_MSG_DEBUG
        then
          l_idx := 3;
          get_string( l_idx, p_buf, l_buf );
          info_msg( utl_i18n.raw_to_char( l_buf, 'AL32UTF8' ) );
        when SSH_MSG_USERAUTH_BANNER
        then
          l_idx := 2;
          get_string( l_idx, p_buf, l_buf );
          info_msg( utl_i18n.raw_to_char( l_buf, 'AL32UTF8' ) );
        when SSH_MSG_KEXINIT
        then
          handle_kex( p_buf );
        else
          null;
      end case;
    end loop;
  end;
  --
  function setup_connection( p_host varchar2, p_port pls_integer )
  return boolean
  is
    l_tmp raw(4);
    l_dummy pls_integer;
  begin
    close_connection;
    info_msg( 'try to connect to ' || p_host || ', port ' || p_port );
    g_con := utl_tcp.open_connection( remote_host => p_host, remote_port => p_port, in_buffer_size => 32767, tx_timeout => 5 );
    loop
      l_tmp := utl_tcp.get_raw( c => g_con, len => 4, peek => true );
      if l_tmp = hextoraw( '5353482D' )
      then
        V_S := utl_tcp.get_raw( c => g_con, len => 8, peek => false );
        if utl_raw.substr( V_S, 5, 3 ) = hextoraw( '322E30' ) -- 2.0
           or utl_raw.substr( V_S, 5, 4 ) = hextoraw( '312E3939' ) -- 1.99
        then
          loop
            l_tmp := utl_tcp.get_raw( c => g_con, len => 1, peek => false );
            exit when l_tmp = hextoraw( '0A' );
            if l_tmp != hextoraw( '0D' )
            then
              V_S := utl_raw.concat( V_S, l_tmp );
            end if;
          end loop;
          l_dummy := utl_tcp.write_raw( g_con, utl_raw.concat( V_C, '0D0A' ) );
        else
          raise_application_error( -20001, 'Invalid server version: ' || utl_raw.cast_to_varchar2( utl_raw.substr( V_S, 5, 4 ) ) );
        end if;
        exit;
      else
        info_msg( utl_tcp.get_line( c => g_con, remove_crlf => true ) );
      end if;
    end loop;
    return true;
  exception
    when others then
    -- ORA-29260: network error: Connect failed because target host or object does not exist
    -- ORA-29260: network error: TNS:no listener
      error_msg( substr( dbms_utility.format_error_backtrace, 1, 255 ) );
      close_connection;
      return false;
  end;
  --
  procedure show_name_list( p_nl tp_name_list )
  is
    l_str varchar2(32767);
  begin
    for i in 1 .. p_nl.count
    loop
      l_str := l_str || ',' || p_nl( i );
    end loop;
    info_msg( ltrim( l_str, ',' ) );
  end;
  --
  procedure change_nl( p_list in out tp_name_list, p_sort varchar2, p_excl varchar2 )
  is
    l_tmp  tp_name_list;
    l_sort tp_name_list;
    l_excl tp_name_list;
    procedure str2name_list( p_str varchar2, p_list out tp_name_list )
    is
      l_idx pls_integer;
      l_str varchar2(32767) := p_str;
    begin
      p_list := tp_name_list();
      loop
        exit when l_str is null;
        l_idx := instr( l_str || ',', ',' );
        p_list.extend;
        p_list( p_list.count ) := substr( l_str, 1, l_idx - 1 );
        l_str := substr( l_str, l_idx + 1 );
      end loop;
    end;
  begin
    l_tmp := tp_name_list();
    str2name_list( p_sort, l_sort );
    str2name_list( p_excl, l_excl );
    for i in 1 .. l_sort.count
    loop
      if l_sort(i) member of p_list and l_sort(i) not member of l_excl
      then
        l_tmp.extend;
        l_tmp( l_tmp.count ) := l_sort(i);
      end if;
    end loop;
    for i in 1 .. p_list.count
    loop
      if p_list(i) not member of l_tmp and p_list(i) not member of l_excl
      then
        l_tmp.extend;
        l_tmp( l_tmp.count ) := p_list(i);
      end if;
    end loop;
    p_list := l_tmp;
  end;
  --
  procedure handle_kex( p_buf raw, p_fingerprint varchar2 := null, p_trust boolean := null )
  is
    l_buf raw(32767);
    l_idx pls_integer;
    l_tmp raw(32767);
    l_hash_type pls_integer;
    l_host_fingerprint varchar2(250);
    --
    kex_algorithms              tp_name_list;
    public_key_algorithms       tp_name_list;
    encr_algo_client_to_server  tp_name_list;
    encr_algo_server_to_client  tp_name_list;
    mac_algo_client_to_server   tp_name_list;
    mac_algo_server_to_client   tp_name_list;
    compr_algo_client_to_server tp_name_list;
    compr_algo_server_to_client tp_name_list;
    languages_client_to_server  tp_name_list;
    languages_server_to_client  tp_name_list;
    my_kex_algorithms              tp_name_list;
    my_public_key_algorithms       tp_name_list;
    my_encr_algo_client_to_server  tp_name_list;
    my_encr_algo_server_to_client  tp_name_list;
    my_mac_algo_client_to_server   tp_name_list;
    my_mac_algo_server_to_client   tp_name_list;
    my_compr_algo_client_to_server tp_name_list;
    my_compr_algo_server_to_client tp_name_list;
    my_languages_client_to_server  tp_name_list;
    my_languages_server_to_client  tp_name_list;
    first_kex_packet_follows boolean;
    --
    l_encr_algo_c   varchar2(100 char);
    l_encr_algo_s   varchar2(100 char);
    l_mac_algo_c    varchar2(100 char);
    l_mac_algo_s    varchar2(100 char);
    l_compr_algo_c  varchar2(100 char);
    l_compr_algo_s  varchar2(100 char);
    l_kex_algorithm varchar2(100 char);
    l_public_key_algorithm varchar2(100 char);
    --
    DH_p  raw(8194);
    DH_g  raw(8194);
    I_C raw(32767);
    I_S raw(32767);
    K_S raw(32767);
    l_x raw(32767);
    l_e raw(32767);
    l_f raw(32767);
    l_s raw(32767);
    l_K raw(32767);
    l_H raw(100);
    --
    cursor c_known_hosts( cp_host varchar2 )
    is
    select fingerprint
    from as_sftp_known_hosts
    where host = cp_host;
    r_known_hosts c_known_hosts%rowtype;
    --
    function derive_key( p_byte raw, p_len pls_integer )
    return raw
    is
      l_rv raw(32767);
      l_tmp raw(32767);
    begin
      append_mpint( l_tmp, l_K );
      l_tmp := utl_raw.concat( l_tmp, l_H );
      l_rv := utl_raw.concat( l_tmp, p_byte, g_session_id );
      l_rv := dbms_crypto.hash( l_rv, l_hash_type );
      loop
        exit when utl_raw.length( l_rv ) >= p_len;
        l_rv := utl_raw.concat( l_rv, dbms_crypto.hash( utl_raw.concat( l_tmp, l_rv ), l_hash_type ) );
      end loop;
      return utl_raw.substr( l_rv, 1, p_len );
    end;
    --
    procedure add2name_list( p_name_list in out tp_name_list, p_val varchar2 )
    is
    begin
      if HMAC_SH256 is not null
      then
        p_name_list.extend;
        p_name_list( p_name_list.count ) := p_val;
      end if;
    end;
    --
    procedure validate_signature( p_host_key raw, p_signature raw )
    is
      l_idx pls_integer;
      l_tmp raw(32767);
      --
      l_p raw(32767);
      l_g raw(32767);
      l_q raw(32767);
      l_y raw(32767);
      l_dss_r raw(200);
      l_dss_s raw(200);
      l_w raw(32767);
      l_u1 raw(32767);
      l_u2 raw(32767);
      l_v raw(32767);
      l_dss_len pls_integer;
      --
      l_rsa_e raw(32767);
      l_rsa_n raw(32767);
      l_rsa_s raw(32767);
      l_hash_len pls_integer;
      l_hash_type pls_integer;
      --
      l_identifier raw(32767);
      l_pub_w raw(32767);
      l_curve tp_ec_curve;
      l_inv tp_mag;
      l_ecdsa_u1 tp_mag;
      l_ecdsa_u2 tp_mag;
      l_ecdsa_r raw(32767);
      l_ecdsa_s raw(32767);
      l_ecdsa_w tp_ec_point;
      l_ecdsa_verify tp_ec_point;
    begin
      l_idx := 1;
      get_string( l_idx, p_host_key, l_tmp );
      debug_msg( 'validating host key using algorithm ' || utl_raw.cast_to_varchar2( l_tmp ) );
      if l_tmp = hextoraw( '7373682D647373' ) -- ssh-dss
      then
        debug_msg( 'trying ' || utl_raw.cast_to_varchar2( l_tmp ) );
        get_mpint( l_idx, p_host_key, l_p );
        get_mpint( l_idx, p_host_key, l_q );
        get_mpint( l_idx, p_host_key, l_g );
        get_mpint( l_idx, p_host_key, l_y );
        l_idx := 1;
        get_string( l_idx, p_signature, l_tmp );
        debug_msg( 'trying signature ' || utl_raw.cast_to_varchar2( l_tmp ) );
        if l_tmp != hextoraw( '7373682D647373' ) -- ssh-dss
        then
          raise_application_error( -20011, 'ssh-dss not OK' );
        end if;
        get_string( l_idx, p_signature, l_tmp );
        l_dss_len := utl_raw.length( l_tmp ) / 2;
        l_dss_r := utl_raw.substr( l_tmp, 1, l_dss_len );
        l_dss_s := utl_raw.substr( l_tmp, l_dss_len + 1 );
		if (  ltrim( rawtohex( l_dss_r ), '0' ) is null
		   or ltrim( rawtohex( l_dss_s ), '0' ) is null
		   )
		then
          raise_application_error( -20013, 'ssh-dss not OK' );
        end if;
        l_w := powmod( l_dss_s, demag( nsub( mag( l_q ), 2 ) ), l_q );
        l_u1 := demag( xmod( rmul( mag( dbms_crypto.hash( l_H, HASH_SH1 ) ), mag( l_w ) ), mag( l_q ) ) );
        l_u2 := demag( xmod( rmul( mag( l_dss_r ), mag( l_w ) ), mag( l_q ) ) );
        l_v := lpad( demag( xmod( xmod( rmul( mag( powmod( l_g, l_u1, l_p ) ), mag( powmod( l_y, l_u2, l_p ) ) ), mag( l_p ) ), mag( l_q ) ) ), l_dss_len * 2, '0' );
        if l_v != l_dss_r
        then
          error_msg( p_host_key );
          error_msg( p_signature );
          error_msg( l_H );
          error_msg( l_dss_r );
          error_msg( l_v );
          error_msg( l_dss_s );
          error_msg( l_w );
          error_msg( l_u1 );
          error_msg( l_u2 );
          raise_application_error( -20012, 'ssh-dss not OK' );
        end if;
      elsif l_tmp in ( hextoraw( '7373682D727361' ) -- ssh-rsa
                     , hextoraw( '7273612D736861322D323536' ) -- rsa-sha2-256
                     , hextoraw( '7273612D736861322D353132' ) -- rsa-sha2-512
                     )
      then
        debug_msg( 'trying ' || utl_raw.cast_to_varchar2( l_tmp ) );
        get_mpint( l_idx, p_host_key, l_rsa_e );
        get_mpint( l_idx, p_host_key, l_rsa_n );
        l_idx := 1;
        get_string( l_idx, p_signature, l_tmp );
        debug_msg( 'trying signature ' || utl_raw.cast_to_varchar2( l_tmp ) );
        if l_tmp = hextoraw( '7373682D727361' ) -- ssh-rsa
        then
          l_hash_len := 20;
          l_hash_type := HASH_SH1;
        elsif l_tmp = hextoraw( '7273612D736861322D323536' ) -- rsa-sha2-256
        then
          l_hash_len := 32;
          l_hash_type := HASH_SH256;
        elsif l_tmp = hextoraw( '7273612D736861322D353132' ) -- rsa-sha2-512
        then
          l_hash_len := 64;
          l_hash_type := HASH_SH512;
        else
          raise_application_error( -20013, 'ssh-rsa not OK' );
        end if;
        get_string( l_idx, p_signature, l_rsa_s );
        l_tmp := powmod( l_rsa_s, l_rsa_e, l_rsa_n );
        if dbms_crypto.hash( l_H, l_hash_type ) != utl_raw.substr( l_tmp, - l_hash_len )
        then
          error_msg( p_host_key );
          error_msg( p_signature );
          error_msg( l_H );
          error_msg( l_rsa_s );
          error_msg( l_rsa_e );
          error_msg( l_rsa_n );
          error_msg( l_hash_len );
          error_msg( l_tmp );
          error_msg( dbms_crypto.hash( l_H, l_hash_type ) );
          raise_application_error( -20015, 'ssh-rsa not OK' );
        end if;
      elsif l_tmp in ( hextoraw( '65636473612D736861322D6E69737470323536' ) -- ecdsa-sha2-nistp256
                     , hextoraw( '65636473612D736861322D6E69737470333834' ) -- ecdsa-sha2-nistp384
                     , hextoraw( '65636473612D736861322D6E69737470353231' ) -- ecdsa-sha2-nistp521
                     )
      then
        debug_msg( 'trying ' || utl_raw.cast_to_varchar2( l_tmp ) );
        get_string( l_idx, p_host_key, l_identifier );
        if l_identifier != utl_raw.substr( l_tmp, - utl_raw.length( l_identifier ) )
        then
          raise_application_error( -20019, 'ECDSA not OK' );
        end if;
        get_named_curve( utl_raw.cast_to_varchar2( l_identifier ), l_curve );
        get_string( l_idx, p_host_key, l_tmp );
        bytes_to_ec_point( l_tmp, l_curve, l_ecdsa_w );
        l_idx := 1;
        get_string( l_idx, p_signature, l_tmp );
        debug_msg( 'trying signature ' || utl_raw.cast_to_varchar2( l_tmp ) );
        if l_tmp = hextoraw( '65636473612D736861322D6E69737470323536' ) -- ecdsa-sha2-nistp256
        then
          l_hash_type := HASH_SH256;
        elsif l_tmp = hextoraw( '65636473612D736861322D6E69737470333834' ) -- ecdsa-sha2-nistp384
        then
          l_hash_type := HASH_SH384;
        elsif l_tmp = hextoraw( '65636473612D736861322D6E69737470353231' ) -- ecdsa-sha2-nistp521
        then
          l_hash_type := HASH_SH512;
        else
          raise_application_error( -20020, 'ECDSA not OK' );
        end if;
        get_string( l_idx, p_signature, l_tmp ); -- signature blob
        l_idx := 1;
        get_mpint( l_idx, l_tmp, l_ecdsa_r );
        get_mpint( l_idx, l_tmp, l_ecdsa_s );
		if (  ltrim( rawtohex( l_ecdsa_r ), '0' ) is null
		   or ltrim( rawtohex( l_ecdsa_s ), '0' ) is null
		   )
		then
          raise_application_error( -20022, 'ECDSA not OK' );
        end if;
        l_inv := powmod( mag( l_ecdsa_s ), nsub( l_curve.group_order, 2 ), l_curve.group_order );
        l_ecdsa_u1 := mulmod( mag( dbms_crypto.hash( l_h, l_hash_type ) ), l_inv, l_curve.group_order );
        l_ecdsa_u2 := mulmod( mag( l_ecdsa_r ), l_inv, l_curve.group_order );
        l_ecdsa_verify := add_point( multiply_point( l_curve.generator, l_ecdsa_u1, l_curve )
                                   , multiply_point( l_ecdsa_w, l_ecdsa_u2, l_curve )
                                   , l_curve );
        if utl_raw.compare( demag( l_ecdsa_verify.x ), ltrim( l_ecdsa_r, '0' ) ) != 0
        then
          error_msg( p_host_key );
          error_msg( p_signature );
          error_msg( l_H );
          raise_application_error( -20021, 'ECDSA not OK' );
        end if;
      elsif l_tmp in ( hextoraw( '7373682D65643235353139' ) -- ssh-ed25519
                     , hextoraw( '7373682D6564343438' )     -- ssh-ed448
                     )
      then
        debug_msg( 'trying ' || utl_raw.cast_to_varchar2( l_tmp ) );
        raise_application_error( -20030, 'EdDSA not yet implemented.' );
      else
        raise_application_error( -20010, 'unexpected public key algorithm ' || utl_raw.cast_to_varchar2( l_tmp ) );
      end if;
    end;
    --
  begin
    I_S := p_buf;
    l_idx := 18;
    kex_algorithms              := read_name_list( l_idx, p_buf );
    public_key_algorithms       := read_name_list( l_idx, p_buf );
    encr_algo_client_to_server  := read_name_list( l_idx, p_buf );
    encr_algo_server_to_client  := read_name_list( l_idx, p_buf );
    mac_algo_client_to_server   := read_name_list( l_idx, p_buf );
    mac_algo_server_to_client   := read_name_list( l_idx, p_buf );
    compr_algo_client_to_server := read_name_list( l_idx, p_buf );
    compr_algo_server_to_client := read_name_list( l_idx, p_buf );
    languages_client_to_server  := read_name_list( l_idx, p_buf );
    languages_server_to_client  := read_name_list( l_idx, p_buf );
    first_kex_packet_follows := utl_raw.compare( utl_raw.substr( p_buf, l_idx, 1 ), '00' ) != 0;
    --
    --show_name_list( kex_algorithms );
    --show_name_list( public_key_algorithms );
    --show_name_list( encr_algo_client_to_server );
    --show_name_list( encr_algo_server_to_client );
    --show_name_list( mac_algo_client_to_server );
    --show_name_list( mac_algo_server_to_client );
    --show_name_list( compr_algo_client_to_server );
    --show_name_list( compr_algo_server_to_client );
    --show_name_list( languages_client_to_server );
    --show_name_list( languages_server_to_client );
    --
    my_kex_algorithms := tp_name_list( 'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1', 'diffie-hellman-group-exchange-sha1' );
    add2name_list( my_kex_algorithms, 'diffie-hellman-group14-sha256' );
    add2name_list( my_kex_algorithms, 'diffie-hellman-group15-sha512' );
    add2name_list( my_kex_algorithms, 'diffie-hellman-group16-sha512' );
    add2name_list( my_kex_algorithms, 'diffie-hellman-group17-sha512' );
    add2name_list( my_kex_algorithms, 'diffie-hellman-group18-sha512' );
    add2name_list( my_kex_algorithms, 'diffie-hellman-group-exchange-sha256' );
    add2name_list( my_kex_algorithms, 'ecdh-sha2-nistp256' );
    add2name_list( my_kex_algorithms, 'ecdh-sha2-nistp384' );
    add2name_list( my_kex_algorithms, 'ecdh-sha2-nistp521' );
    my_public_key_algorithms := tp_name_list( 'ssh-dss', 'ssh-rsa' );
    add2name_list( my_public_key_algorithms, 'rsa-sha2-256' );
    add2name_list( my_public_key_algorithms, 'rsa-sha2-512' );
--    add2name_list( my_public_key_algorithms, 'ssh-ed25519' );
    add2name_list( my_public_key_algorithms, 'ecdsa-sha2-nistp256' );
    add2name_list( my_public_key_algorithms, 'ecdsa-sha2-nistp384' );
    add2name_list( my_public_key_algorithms, 'ecdsa-sha2-nistp521' );
    my_encr_algo_client_to_server := tp_name_list( 'aes128-cbc', 'aes128-ctr', '3des-cbc' );
    add2name_list( my_encr_algo_client_to_server, 'aes256-ctr' );
    add2name_list( my_encr_algo_client_to_server, 'aes256-cbc' );
    add2name_list( my_encr_algo_client_to_server, 'aes192-ctr' );
    add2name_list( my_encr_algo_client_to_server, 'aes192-cbc' );
    my_encr_algo_server_to_client := tp_name_list( 'aes128-cbc', 'aes128-ctr', '3des-cbc' );
    add2name_list( my_encr_algo_server_to_client, 'aes256-cbc' );
    add2name_list( my_encr_algo_server_to_client, 'aes256-ctr' );
    add2name_list( my_encr_algo_server_to_client, 'aes192-cbc' );
    add2name_list( my_encr_algo_server_to_client, 'aes192-ctr' );
    my_mac_algo_client_to_server := tp_name_list( 'hmac-sha1', 'hmac-md5' );
    add2name_list( my_mac_algo_client_to_server, 'hmac-sha2-256' );
    add2name_list( my_mac_algo_client_to_server, 'hmac-sha2-512' );
    my_mac_algo_server_to_client := my_mac_algo_client_to_server;
    my_compr_algo_client_to_server := tp_name_list( 'none' );
    my_compr_algo_server_to_client := tp_name_list( 'none' );
    --
    change_nl( my_kex_algorithms            , my_globals.preferred_kex_algos, my_globals.excluded_kex_algos );
    change_nl( my_encr_algo_client_to_server, my_globals.preferred_encr_algos, my_globals.excluded_encr_algos );
    change_nl( my_encr_algo_server_to_client, my_globals.preferred_encr_algos, my_globals.excluded_encr_algos );
    change_nl( my_public_key_algorithms     , my_globals.preferred_pkey_algos, my_globals.excluded_pkey_algos );
    --
    I_C := utl_raw.concat( SSH_MSG_KEXINIT
                         , dbms_crypto.randombytes( 16 )
                         );
    append_name_list( I_C, my_kex_algorithms );
    append_name_list( I_C, my_public_key_algorithms );
    append_name_list( I_C, my_encr_algo_client_to_server );
    append_name_list( I_C, my_encr_algo_server_to_client );
    append_name_list( I_C, my_mac_algo_client_to_server );
    append_name_list( I_C, my_mac_algo_server_to_client );
    append_name_list( I_C, my_compr_algo_client_to_server );
    append_name_list( I_C, my_compr_algo_server_to_client );
    append_name_list( I_C, my_languages_client_to_server );
    append_name_list( I_C, my_languages_server_to_client );
    append_boolean( I_C, false );
    I_C := utl_raw.concat( I_C, '00000000' );
    write_packet( I_C );
    --
    for i in my_encr_algo_client_to_server.first .. my_encr_algo_client_to_server.last
    loop
      if my_encr_algo_client_to_server(i) member of encr_algo_client_to_server
      then
        l_encr_algo_c := my_encr_algo_client_to_server(i);
        exit;
      end if;
    end loop;
    if l_encr_algo_c is null
    then
      error_msg( 'as_sftp algorithms' );
      show_name_list( my_encr_algo_client_to_server );
      error_msg( 'server algorithms' );
      show_name_list( encr_algo_client_to_server );
      raise_application_error( -20002, 'Could not find matching encryption algorithm client to server' );
    end if;
    --
    for i in my_encr_algo_server_to_client.first .. my_encr_algo_server_to_client.last
    loop
      if my_encr_algo_server_to_client(i) member of encr_algo_server_to_client
      then
        l_encr_algo_s := my_encr_algo_server_to_client(i);
        exit;
      end if;
    end loop;
    if l_encr_algo_s is null
    then
      error_msg( 'as_sftp algorithms' );
      show_name_list( my_encr_algo_server_to_client );
      error_msg( 'server algorithms' );
      show_name_list( encr_algo_server_to_client );
      raise_application_error( -20003, 'Could not find matching encryption algorithm server to client' );
    end if;
    info_msg( 'using ' || l_encr_algo_c || ', ' || l_encr_algo_s );
    --
    for i in my_mac_algo_client_to_server.first .. my_mac_algo_client_to_server.last
    loop
      if my_mac_algo_client_to_server(i) member of mac_algo_client_to_server
      then
        l_mac_algo_c := my_mac_algo_client_to_server(i);
        exit;
      end if;
    end loop;
    if l_mac_algo_c is null
    then
      raise_application_error( -20004, 'Could not find matching mac algorithm client to server' );
    end if;
    --
    for i in my_mac_algo_server_to_client.first .. my_mac_algo_server_to_client.last
    loop
      if my_mac_algo_server_to_client(i) member of mac_algo_server_to_client
      then
        l_mac_algo_s := my_mac_algo_server_to_client(i);
        exit;
      end if;
    end loop;
    if l_mac_algo_s is null
    then
      raise_application_error( -20005, 'Could not find matching mac algorithm server to client' );
    end if;
    info_msg( 'using ' || l_mac_algo_c || ', ' || l_mac_algo_s );
    --
    for i in my_compr_algo_client_to_server.first .. my_compr_algo_client_to_server.last
    loop
      if my_compr_algo_client_to_server(i) member of compr_algo_client_to_server
      then
        l_compr_algo_c := my_compr_algo_client_to_server(i);
        exit;
      end if;
    end loop;
    if l_compr_algo_c is null
    then
      raise_application_error( -20006, 'Could not find matching compression algorithm client to server' );
    end if;
    --
    for i in my_compr_algo_server_to_client.first .. my_compr_algo_server_to_client.last
    loop
      if my_compr_algo_server_to_client(i) member of compr_algo_server_to_client
      then
        l_compr_algo_s := my_compr_algo_server_to_client(i);
        exit;
      end if;
    end loop;
    if l_compr_algo_s is null
    then
      raise_application_error( -20007, 'Could not find matching compression algorithm server to client' );
    end if;
    --
    for i in my_public_key_algorithms.first .. my_public_key_algorithms.last
    loop
      if my_public_key_algorithms(i) member of public_key_algorithms
      then
        l_public_key_algorithm := my_public_key_algorithms(i);
        exit;
      end if;
    end loop;
    if l_public_key_algorithm is null
    then
      error_msg( 'as_sftp algorithms' );
      show_name_list( my_public_key_algorithms );
      error_msg( 'server algorithms' );
      show_name_list( public_key_algorithms );
      raise_application_error( -20008, 'Could not find matching public key algorithm' );
    end if;
    info_msg( 'using ' || l_public_key_algorithm );
    --
    for i in my_kex_algorithms.first .. my_kex_algorithms.last
    loop
      if my_kex_algorithms(i) member of kex_algorithms
      then
        l_kex_algorithm := my_kex_algorithms(i);
        exit;
      end if;
    end loop;
    info_msg( 'using ' || l_kex_algorithm );
  --
    if l_kex_algorithm = 'diffie-hellman-group1-sha1'
    then
      DH_p := 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF';
      DH_g := '02';
      l_hash_type := HASH_SH1;
      l_buf := SSH_MSG_KEXDH_INIT;
    elsif l_kex_algorithm in ( 'diffie-hellman-group14-sha1'
                             , 'diffie-hellman-group14-sha256'
                             )
    then
      DH_p := 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF';
      DH_g := '02';
      if l_kex_algorithm = 'diffie-hellman-group14-sha1'
      then
        l_hash_type := HASH_SH1;
      else
        l_hash_type := HASH_SH256;
      end if;
      l_buf := SSH_MSG_KEXDH_INIT;
    elsif l_kex_algorithm = 'diffie-hellman-group15-sha512'
    then
      DH_p := 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';
      DH_g := '02';
      l_hash_type := HASH_SH512;
      l_buf := SSH_MSG_KEXDH_INIT;
    elsif l_kex_algorithm = 'diffie-hellman-group16-sha512'
    then
      DH_p := 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF';
      DH_g := '02';
      l_hash_type := HASH_SH512;
      l_buf := SSH_MSG_KEXDH_INIT;
    elsif l_kex_algorithm = 'diffie-hellman-group17-sha512'
    then
      DH_p := 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF';
      DH_g := '02';
      l_hash_type := HASH_SH512;
      l_buf := SSH_MSG_KEXDH_INIT;
    elsif l_kex_algorithm = 'diffie-hellman-group18-sha512'
    then
      DH_p := 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF';
      DH_g := '02';
      l_hash_type := HASH_SH512;
      l_buf := SSH_MSG_KEXDH_INIT;
    elsif l_kex_algorithm in ( 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group-exchange-sha256' )
    then
      if l_kex_algorithm = 'diffie-hellman-group-exchange-sha1'
      then
        l_hash_type := HASH_SH1;
      else
        l_hash_type := HASH_SH256;
      end if;
      l_buf := SSH_MSG_KEX_DH_GEX_REQUEST;
      append_int32( l_buf, 1024 );
      append_int32( l_buf, 2048 );
      append_int32( l_buf, 8192 );
      write_packet( l_buf );
      read_until( l_buf, SSH_MSG_KEX_DH_GEX_GROUP );
      l_idx := 2;
      get_mpint( l_idx, l_buf, DH_p );
      get_mpint( l_idx, l_buf, DH_g );
      l_buf := SSH_MSG_KEX_DH_GEX_INIT;
    elsif l_kex_algorithm in ( 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521' )
    then
      declare
        l_qc raw(3999);
        l_qs raw(3999);
        l_curve tp_ec_curve;
        l_pb tp_ec_point;
        l_xxx tp_mag;
      begin
        l_buf := SSH_MSG_KEX_ECDH_INIT;
        if l_kex_algorithm = 'ecdh-sha2-nistp256'
        then
          l_hash_type := HASH_SH256;
        elsif l_kex_algorithm = 'ecdh-sha2-nistp384'
        then
          l_hash_type := HASH_SH384;
        elsif l_kex_algorithm = 'ecdh-sha2-nistp521'
        then
          l_hash_type := HASH_SH512;
        end if;
        l_xxx := mag( dbms_crypto.randombytes( 4 ) );
        get_named_curve( substr( l_kex_algorithm, -8 ), l_curve );
        l_pb  := multiply_point( l_curve.generator, l_xxx, l_curve );
        l_qc := utl_raw.concat( '04', lpad( demag( l_pb.x ), 2 * l_curve.nlen, '0' ), lpad( demag( l_pb.y ), 2 * l_curve.nlen, '0' ) );
        append_mpint( l_buf, l_qc );
        write_packet( l_buf );
        read_until( l_buf, SSH_MSG_KEX_ECDH_REPLY );
        l_idx := 2;
        get_string( l_idx, l_buf, K_S );
        get_string( l_idx, l_buf, l_qs );
        get_string( l_idx, l_buf, l_s );
        bytes_to_ec_point( l_qs, l_curve, l_pb );
        l_pb  := multiply_point( l_pb, l_xxx, l_curve );
        l_K := demag( l_pb.x );
        l_tmp := null;
        append_string( l_tmp, V_C );
        append_string( l_tmp, V_S );
        append_string( l_tmp, I_C );
        append_string( l_tmp, I_S );
        append_string( l_tmp, K_S );
        append_mpint( l_tmp, l_qc );
        append_mpint( l_tmp, l_qs );
        append_mpint( l_tmp, l_K );
        l_H := dbms_crypto.hash( l_tmp, l_hash_type );
      end;
    else
      raise_application_error( -20009, 'Could not find matching kex algorithm' );
    end if;
  --
    if l_kex_algorithm not in ( 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521' )
    then
      l_x := dbms_crypto.randombytes( 10 );
      l_e := powmod( DH_g, l_x, DH_p );
      append_mpint( l_buf, l_e );
      write_packet( l_buf );
      read_until( l_buf, SSH_MSG_KEXDH_REPLY, SSH_MSG_KEX_DH_GEX_REPLY );
      case utl_raw.substr( l_buf, 1, 1 )
        when SSH_MSG_KEXDH_REPLY
        then
          l_idx := 2;
          get_string( l_idx, l_buf, K_S );
          get_mpint( l_idx, l_buf, l_f ); -- f
          l_K := powmod( l_f, l_x, DH_p );
          l_tmp := null;
          append_string( l_tmp, V_C );
          append_string( l_tmp, V_S );
          append_string( l_tmp, I_C );
          append_string( l_tmp, I_S );
          append_string( l_tmp, K_S );
          append_mpint( l_tmp, l_e );
          append_mpint( l_tmp, l_f );
          append_mpint( l_tmp, l_K );
          l_H := dbms_crypto.hash( l_tmp, l_hash_type );
          get_string( l_idx, l_buf, l_s );
        when SSH_MSG_KEX_DH_GEX_REPLY
        then
          l_idx := 2;
          get_string( l_idx, l_buf, K_S );
          get_mpint( l_idx, l_buf, l_f ); -- f
          l_K := powmod( l_f, l_x, DH_p );
          l_tmp := null;
          append_string( l_tmp, V_C );
          append_string( l_tmp, V_S );
          append_string( l_tmp, I_C );
          append_string( l_tmp, I_S );
          append_string( l_tmp, K_S );
          append_int32( l_tmp, 1024 );
          append_int32( l_tmp, 2048 );
          append_int32( l_tmp, 8192 );
          append_mpint( l_tmp, DH_p );
          append_mpint( l_tmp, DH_G );
          append_mpint( l_tmp, l_e );
          append_mpint( l_tmp, l_f );
          append_mpint( l_tmp, l_K );
          l_H := dbms_crypto.hash( l_tmp, l_hash_type );
          get_string( l_idx, l_buf, l_s );
      end case;
    end if;
    validate_signature( K_S, l_s );
    info_msg( 'signature OK' );
    --
    if HASH_SH256 is null
    then
      l_host_fingerprint := dbms_crypto.hash( K_S, HASH_MD5 );
      l_host_fingerprint := regexp_replace( l_host_fingerprint, '(..)', '\1:' );
      l_host_fingerprint := 'MD5:' || lower( rtrim( l_host_fingerprint, ':' ) );
    else
      l_host_fingerprint := utl_encode.base64_encode( dbms_crypto.hash( K_S, HASH_SH256 ) );
      l_host_fingerprint := 'SHA256:' || utl_raw.cast_to_varchar2( l_host_fingerprint );
    end if;
    info_msg( 'host fingerprint: ' || l_host_fingerprint );
    --
    if    l_host_fingerprint = lower( p_fingerprint )
       or l_host_fingerprint = 'MD5:' || lower( p_fingerprint )
       or l_host_fingerprint = 'SHA256:' || p_fingerprint
       or p_trust
    then
      merge into as_sftp_known_hosts
      using ( select upper( g_con.remote_host ) p_host from dual ) on ( host = p_host )
      when matched then
        update set fingerprint = l_host_fingerprint
      when not matched then
        insert( host, fingerprint ) values( p_host, l_host_fingerprint );
      commit;
    else
      open c_known_hosts( upper( g_con.remote_host ) );
      fetch c_known_hosts into r_known_hosts;
      if c_known_hosts%notfound
      then
        r_known_hosts.fingerprint := null;
      end if;
      close c_known_hosts;
      if l_host_fingerprint = r_known_hosts.fingerprint
      then
        null; -- OK
      else
        raise_application_error( -20017, 'Host fingerprint not OK.' );
      end if;
    end if;
    --
    write_packet( SSH_MSG_NEWKEYS );
    read_until( l_buf, SSH_MSG_NEWKEYS );
    g_encr_algo_c := l_encr_algo_c;
    g_encr_algo_s := l_encr_algo_s;
    g_mac_algo_c := l_mac_algo_c;
    g_mac_algo_s := l_mac_algo_s;
    g_compr_algo_c := l_compr_algo_c;
    g_compr_algo_s := l_compr_algo_s;
    if g_session_id is null
    then
      g_session_id := l_H;
    end if;
    g_iv_cypher_c2s := derive_key( '41' -- A
                                 , case when g_encr_algo_c in ( '3des-cbc', '3des-ctr' ) then 8 else 16 end
                                 );
    g_iv_cypher_s2c := derive_key( '42' -- B
                                 , case when g_encr_algo_s in ( '3des-cbc', '3des-ctr' ) then 8 else 16 end
                                 );
    g_iv_cypher_s2c_ctr := to_number( g_iv_cypher_s2c, rpad( 'X', 32, 'X' ) );
    g_key_cypher_c2s := derive_key( '43' -- C
                                  , case g_encr_algo_c
                                      when '3des-cbc' then 24
                                      when '3des-ctr' then 24
                                      when 'aes192-cbc' then 24
                                      when 'aes192-ctr' then 24
                                      when 'aes256-cbc' then 32
                                      when 'aes256-ctr' then 32
                                      when 'arcfour256' then 32
                                      when 'rijndael256-cbc' then 32
                                      when 'rijndael-cbc@lysator.liu.se' then 32
                                      when 'rijndael192-cbc' then 24
                                      else 16
                                    end
                                  );
    g_key_cypher_s2c := derive_key( '44' -- D
                                  , case g_encr_algo_s
                                      when '3des-cbc' then 24
                                      when '3des-ctr' then 24
                                      when 'aes192-cbc' then 24
                                      when 'aes192-ctr' then 24
                                      when 'aes256-cbc' then 32
                                      when 'aes256-ctr' then 32
                                      when 'arcfour256' then 32
                                      when 'rijndael256-cbc' then 32
                                      when 'rijndael-cbc@lysator.liu.se' then 32
                                      when 'rijndael192-cbc' then 24
                                      else 16
                                    end
                                  );
    g_key_mac_c2s := derive_key( '45' -- E
                               , case
                                   when g_mac_algo_c in ( 'hmac-sha1', 'hmac-sha1-96', 'hmac-ripemd160' ) then 20
                                   when g_mac_algo_c in ( 'hmac-sha2-256' ) then 32
                                   when g_mac_algo_c in ( 'hmac-sha2-512' ) then 64
                                   else 16
                                 end
                               );
    g_key_mac_s2c := derive_key( '46' -- F
                               , case
                                   when g_mac_algo_s in ( 'hmac-sha1', 'hmac-sha1-96', 'hmac-ripemd160' ) then 20
                                   when g_mac_algo_s in ( 'hmac-sha2-256' ) then 32
                                   when g_mac_algo_s in ( 'hmac-sha2-512' ) then 64
                                   else 16
                                end
                               );
  end;
  --
  function get_len( p_key raw, p_ind in out pls_integer )
  return pls_integer
  is
    l_len pls_integer;
    l_tmp pls_integer;
  begin
    p_ind := p_ind + 1;
    l_len := to_number( utl_raw.substr( p_key, p_ind, 1 ), 'xx' );
    if l_len > 127
    then
      l_tmp := l_len - 128;
      p_ind := p_ind + 1;
      l_len := to_number( utl_raw.substr( p_key, p_ind, l_tmp ), rpad( 'x', 2 * l_tmp, 'x' ) );
      p_ind := p_ind + l_tmp;
    else
      p_ind := p_ind + 1;
    end if;
    return l_len;
  end;
  --
  function get_bytes( p_type raw, p_key raw, p_ind in out pls_integer, p_msg varchar2 := '', p_skip_enclosing_context boolean := true )
  return raw
  is
    l_first raw(1);
    l_len pls_integer;
  begin
    l_first := utl_raw.substr( p_key, p_ind, 1 );
    if l_first != p_type
    then
      if p_skip_enclosing_context and utl_raw.bit_and( l_first, 'C0' ) = '80'
      then
        l_len := get_len( p_key, p_ind );
        return get_bytes( p_type, p_key, p_ind, p_msg, p_skip_enclosing_context );
      else
        if p_msg is not null
        then
          error_msg( p_msg );
        end if;
        raise value_error;
      end if;
    end if;
    l_len := get_len( p_key, p_ind );
    p_ind := p_ind + l_len;
    return utl_raw.substr( p_key, p_ind - l_len, l_len );
  end;
  --
  function get_integer( p_key raw, p_ind in out pls_integer, p_msg varchar2 := '' )
  return raw
  is
  begin
    return get_bytes( c_INTEGER, p_key, p_ind, p_msg );
  end;
  --
  function get_octect( p_key raw, p_ind in out pls_integer, p_msg varchar2 := '' )
  return raw
  is
  begin
    return get_bytes( c_OCTECT, p_key, p_ind, p_msg );
  end;
  --
  function get_oid( p_key raw, p_ind in out pls_integer, p_msg varchar2 := '' )
  return raw
  is
  begin
    return get_bytes( c_OID, p_key, p_ind, p_msg );
  end;
  --
  function get_bit_string( p_key raw, p_ind in out pls_integer, p_msg varchar2 := '' )
  return raw
  is
  begin
    -- assume always primitive encoding
    -- skip unused bits value, assume always 0
    return utl_raw.substr( get_bytes( c_BIT_STRING, p_key, p_ind, p_msg ), 2 );
  end;
  --
  procedure check_tag( p_key raw, p_ind in out pls_integer, p_tag raw, p_msg varchar2 )
  is
  begin
    if utl_raw.substr( p_key, p_ind, 1 ) != p_tag
    then
      debug_msg( p_msg );
      raise value_error;
    end if;
  end;
  --
  procedure check_and_skip_tag( p_key raw, p_ind in out pls_integer, p_tag raw, p_msg varchar2 )
  is
    l_len pls_integer;
  begin
    check_tag( p_key, p_ind, p_tag, p_msg );
    l_len := get_len( p_key, p_ind );
  end;
  --
  procedure check_starting_sequence( p_key raw, p_ind in out pls_integer )
  is
  begin
    p_ind := 1;
    check_and_skip_tag( p_key, p_ind, c_SEQUENCE, 'Does not start with SEQUENCE' );
  end;
  --
  function parse_der_pkcs8( p_key raw, p_pk_parameters out tp_pk_parameters )
  return boolean
  is
    l_rv boolean := false;
    l_dummy raw(3999);
    l_oid raw(3999);
    l_ind pls_integer;
    l_len pls_integer;
    l_ind_pk pls_integer;
    --
    function get_rfc8410_pub_key( p_key raw, p_ind in out pls_integer )
    return raw
    is
      l_rv raw(3999);
      l_len pls_integer;
      l_key_len pls_integer;
    begin
      l_key_len := utl_raw.length( p_key );
      if l_ind > l_key_len
      then
        return null;
      end if;
      if utl_raw.substr( p_key, p_ind, 1 ) in  ( '80' -- primitive   Context-specific tag 0
                                               , 'A0' -- constructed Context-specific tag 0
                                               )
      then -- skip this tag
        l_len := get_len( p_key, p_ind );
        p_ind := p_ind + l_len;
      end if;
      if l_ind > l_key_len
      then
        return null;
      end if;
      if utl_raw.substr( p_key, p_ind, 1 ) = '81' -- primitive   Context-specific tag 1
      then
        l_rv := get_bytes( utl_raw.substr( p_key, p_ind, 1 ), p_key, p_ind );
      elsif utl_raw.substr( p_key, p_ind, 1 ) = 'A1' -- constructed Context-specific tag 1
      then
        l_len := get_len( p_key, p_ind ); -- skip len
        if utl_raw.substr( p_key, p_ind, 1 ) = c_BIT_STRING
        then
          l_rv := get_bit_string( p_key, p_ind, 'No public key BIT STRING' );
        elsif utl_raw.substr( p_key, p_ind, 1 ) = c_OCTECT
        then
          l_rv := get_octect( p_key, p_ind, 'No public key OCTECT' );
        end if;
      end if;
      return l_rv;
    end;
    --
  begin
    check_starting_sequence( p_key, l_ind );
    l_dummy := get_integer( p_key, l_ind, 'No PKCS#8 version' );  -- version
    check_tag( p_key, l_ind, c_SEQUENCE, 'pkcs#8 no sequence 1' );
    l_len := get_len( p_key, l_ind );
    l_ind_pk := l_ind + l_len;
    l_oid := get_oid( p_key, l_ind );
    debug_msg( 'pkcs#8 OID: ' || l_oid );
    if l_oid = '2A864886F70D010101' -- 1.2.840.113549.1.1.1 rsaEncryption
    then
      debug_msg( 'pkcs#8 RSA' );
      l_ind := l_ind_pk;
      check_and_skip_tag( p_key, l_ind, c_OCTECT, 'pkcs#8 no octect 1' );
      check_and_skip_tag( p_key, l_ind, c_SEQUENCE, 'pkcs#8 no sequence 1' );
      l_dummy := get_integer( p_key, l_ind, 'No version INTEGER' );
      p_pk_parameters(1) := get_integer( p_key, l_ind, 'No modulus INTEGER' );
      p_pk_parameters(2) := get_integer( p_key, l_ind, 'No publicExponent INTEGER' );
      p_pk_parameters(3) := get_integer( p_key, l_ind, 'No privateExponent INTEGER' );
      p_pk_parameters(0) := utl_raw.cast_to_raw( 'RSA' );
      l_rv := true;
    elsif l_oid = '2A8648CE3D0201' -- 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
    then
      debug_msg( 'pkcs#8 nist EC' );
      l_oid := get_oid( p_key, l_ind, 'No EC OID' );
      debug_msg( 'nist EC OID: ' || l_oid );
      if l_oid not in ( '2A8648CE3D030107' -- 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
                      , '2B81040022'       -- 1.3.132.0.34 secp384r1 (SECG (Certicom) named elliptic curve)
                      , '2B81040023'       -- 1.3.132.0.35 secp521r1 (SECG (Certicom) named elliptic curve)
                      )
      then
        raise value_error;
      end if;
      case l_oid
        when '2A8648CE3D030107'
        then
          p_pk_parameters(1) := utl_raw.cast_to_raw( 'nistp256' );
        when '2B81040022'
        then
          p_pk_parameters(1) := utl_raw.cast_to_raw( 'nistp384' );
        when '2B81040023'
        then
          p_pk_parameters(1) := utl_raw.cast_to_raw( 'nistp521' );
      end case;
      check_and_skip_tag( p_key, l_ind, c_OCTECT, 'pkcs#8 no octect 3' );
      check_and_skip_tag( p_key, l_ind, c_SEQUENCE, 'pkcs#8 no sequence 2' );
      l_dummy := get_integer( p_key, l_ind, 'No version INTEGER' );
      p_pk_parameters(3) := get_octect( p_key, l_ind, 'No private key OCTECT' );
      p_pk_parameters(2) := get_rfc8410_pub_key( p_key, l_ind );
      if p_pk_parameters(2) is null
      then
        declare
          l_curve tp_ec_curve;
          l_pb tp_ec_point;
        begin
          get_named_curve( utl_raw.cast_to_varchar2( p_pk_parameters(1) ), l_curve );
          l_pb := multiply_point( l_curve.generator, mag( p_pk_parameters(3) ), l_curve );
          p_pk_parameters(2) := utl_raw.concat( '04', lpad( demag( l_pb.x ), 2 * l_curve.nlen, '0' ), lpad( demag( l_pb.y ), 2 * l_curve.nlen, '0' ) );
        end;
      end if;
      p_pk_parameters(5) := l_oid;
      p_pk_parameters(0) := utl_raw.cast_to_raw( 'EC' );
      l_rv := true;
    elsif l_oid = '2A8648CE380401' -- 1.2.840.10040.4.1 dsa (ANSI X9.57 algorithm)
    then
      debug_msg( 'pkcs#8 DSA' );
      check_and_skip_tag( p_key, l_ind, c_SEQUENCE, 'pkcs#8 no sequence 3' );
      p_pk_parameters(1) := get_integer( p_key, l_ind, 'No P INTEGER' );
      p_pk_parameters(2) := get_integer( p_key, l_ind, 'No Q INTEGER' );
      p_pk_parameters(3) := get_integer( p_key, l_ind, 'No G INTEGER' );
      check_and_skip_tag( p_key, l_ind, c_OCTECT, 'pkcs#8 no octect 4' );
      p_pk_parameters(5) := get_integer( p_key, l_ind, 'No X INTEGER' ); -- private
      p_pk_parameters(4) := powmod( p_pk_parameters(3), p_pk_parameters(5), p_pk_parameters(1) ); -- public
      p_pk_parameters(0) := utl_raw.cast_to_raw( 'DSA' );
      l_rv := true;
    else
      raise value_error;
    end if;
    return l_rv;
  exception
    when value_error
    then
      p_pk_parameters.delete;
      error_msg( 'could not parse key: ' || p_key );
      return false;
  end;
  --
  function parse_private_key( p_key varchar2
                            , p_passphrase varchar2 := null
                            , p_pk_parameters out tp_pk_parameters
                            )
  return boolean
  is
    l_pw raw(32767);
    l_key varchar2(32767);
  --
    function base64_or_decrypt_pk( p_key varchar2, p_pw raw, p_type varchar2 )
    return raw
    is
      l_len pls_integer := length( p_type );
      l_key varchar2(32767);
      l_pos pls_integer;
      l_pos2 pls_integer;
      l_algo varchar2(200);
      l_iv   varchar2(200);
      l_tmp raw(200);
      l_key_size pls_integer;
      l_encr_key raw(200);
      l_encr_algo pls_integer;
    begin
      if (  substr( p_key, 1, 6 + l_len ) != 'BEGIN ' || p_type
         or substr( p_key, - 4 - l_len ) != 'END ' || p_type
         )
      then
        return null;
      end if;
      l_key := ltrim( substr( p_key, 7 + l_len ), '-' || chr(10) || chr(13) );
      l_key := rtrim( substr( l_key, 1, length( l_key ) - 4 - l_len ), '-' || chr(10) || chr(13) );
      if l_pw is not null and substr( l_key, 1, 10 ) = 'Proc-Type:'
      then
        l_pos := instr( l_key, 'DEK-Info:' );
        l_pos2 := instr( l_key, ',', l_pos );
        l_algo := ltrim( substr( l_key, l_pos + 9, l_pos2 - l_pos - 9 ) );
        if l_algo = 'DES-EDE3-CBC'
        then
          l_key_size := 24;
          l_encr_algo := dbms_crypto.encrypt_3des;
        elsif l_algo = 'AES-128-CBC'
        then
          l_key_size := 16;
          l_encr_algo := dbms_crypto.encrypt_aes128;
        elsif l_algo = 'AES-192-CBC'
        then
          l_key_size := 24;
          l_encr_algo := dbms_crypto.encrypt_aes192;
        elsif l_algo = 'AES-256-CBC'
        then
          l_key_size := 32;
          l_encr_algo := dbms_crypto.encrypt_aes256;
        else
          return null;
        end if;
        l_pos := l_pos2;
        l_pos2 := instr( l_key, chr(10), l_pos );
        l_iv := substr( l_key, l_pos + 1, l_pos2 - l_pos - 1 );
        l_iv := rtrim( ltrim( l_iv ), ' ' || chr(10) || chr(13) );
        l_key := substr( l_key, l_pos2 + 1 );
        l_key := ltrim( l_key, ' ' || chr(10) || chr(13) );
        l_tmp := utl_raw.concat( p_pw, utl_raw.substr( l_iv, 1, 8 ) );
        loop
          l_tmp := dbms_crypto.hash( l_tmp, dbms_crypto.hash_md5 );
          l_encr_key := utl_raw.concat( l_encr_key, l_tmp );
          exit when utl_raw.length( l_encr_key ) >= l_key_size;
          l_tmp := utl_raw.concat( l_tmp, p_pw, utl_raw.substr( l_iv, 1, 8 ) );
        end loop;
        l_encr_key := utl_raw.substr( l_encr_key, 1, l_key_size );
        return dbms_crypto.decrypt( utl_encode.base64_decode( utl_raw.cast_to_raw( l_key ) )
                                  , l_encr_algo + dbms_crypto.chain_cbc + dbms_crypto.PAD_PKCS5
                                  , l_encr_key, l_iv );
      end if;
      return utl_encode.base64_decode( utl_raw.cast_to_raw( l_key ) );
    exception
      when others then
        error_msg( 'decrypt_private_key: ' || sqlerrm );
        return null;
    end;
    --
    function parse_RSA_private_key( p_key varchar2, p_pw raw, p_pk_parameters out tp_pk_parameters )
    return boolean
    is
      l_key raw(32767);
      l_dummy raw(3999);
      l_ind pls_integer;
    begin
      p_pk_parameters.delete;
      l_key := base64_or_decrypt_pk( p_key, p_pw, 'RSA PRIVATE KEY' );
      if l_key is null
      then
        return false;
      end if;
      check_starting_sequence( l_key, l_ind );
      l_dummy := get_integer( l_key, l_ind, 'No version INTEGER' );
      p_pk_parameters(1) := get_integer( l_key, l_ind, 'No modulus INTEGER' );
      p_pk_parameters(2) := get_integer( l_key, l_ind, 'No publicExponent INTEGER' );
      p_pk_parameters(3) := get_integer( l_key, l_ind, 'No privateExponent INTEGER' );
      l_dummy := get_integer( l_key, l_ind, 'No prime1 INTEGER' );
      l_dummy := get_integer( l_key, l_ind, 'No prime2 INTEGER' );
      l_dummy := get_integer( l_key, l_ind, 'No exponent1 INTEGER' );
      l_dummy := get_integer( l_key, l_ind, 'No exponent2 INTEGER' );
      l_dummy := get_integer( l_key, l_ind, 'No coefficient INTEGER' );
      p_pk_parameters(0) := utl_raw.cast_to_raw( 'RSA' );
      return true;
    exception when value_error
      then
        p_pk_parameters.delete;
        return false;
    end;
    --
    function parse_DSA_private_key( p_key varchar2, p_pw raw, p_pk_parameters out tp_pk_parameters )
    return boolean
    is
      l_key raw(32767);
      l_dummy raw(3999);
      l_ind pls_integer;
    begin
      p_pk_parameters.delete;
      l_key := base64_or_decrypt_pk( p_key, p_pw, 'DSA PRIVATE KEY' );
      if l_key is null
      then
        return false;
      end if;
      check_starting_sequence( l_key, l_ind );
      l_dummy := get_integer( l_key, l_ind, 'No (dummy) INTEGER 0' );
      p_pk_parameters(1) := get_integer( l_key, l_ind, 'No P INTEGER' );
      p_pk_parameters(2) := get_integer( l_key, l_ind, 'No Q INTEGER' );
      p_pk_parameters(3) := get_integer( l_key, l_ind, 'No G INTEGER' );
      p_pk_parameters(4) := get_integer( l_key, l_ind, 'No Y INTEGER' ); -- public
      p_pk_parameters(5) := get_integer( l_key, l_ind, 'No X INTEGER' ); -- private
      p_pk_parameters(0) := utl_raw.cast_to_raw( 'DSA' );
      return true;
    exception when value_error
      then
        p_pk_parameters.delete;
        return false;
    end;
    --
    function parse_EC_private_key( p_key varchar2, p_pw raw, p_pk_parameters out tp_pk_parameters )
    return boolean
    is
      l_key raw(32767);
      l_dummy raw(3999);
      l_ind pls_integer;
    begin
      p_pk_parameters.delete;
      l_key := base64_or_decrypt_pk( p_key, p_pw, 'EC PRIVATE KEY' );
      if l_key is null
      then
        return false;
      end if;
      check_starting_sequence( l_key, l_ind );
      l_dummy := get_integer( l_key, l_ind, 'No version INTEGER' );
      p_pk_parameters(3) := get_octect( l_key, l_ind, 'No private key OCTECT' );
      p_pk_parameters(5) := get_oid( l_key, l_ind, 'No EC OID' );
      p_pk_parameters(2) := get_bit_string( l_key, l_ind, 'No public key BIT STRING' );
      case p_pk_parameters(5)
        when '2A8648CE3D030107'
        then
          p_pk_parameters(1) := utl_raw.cast_to_raw( 'nistp256' );
        when '2B81040022'
        then
          p_pk_parameters(1) := utl_raw.cast_to_raw( 'nistp384' );
        when '2B81040023'
        then
          p_pk_parameters(1) := utl_raw.cast_to_raw( 'nistp521' );
        else
          error_msg( 'Not implemented OID ' || p_pk_parameters(5) );
          raise value_error;
      end case;
      p_pk_parameters(0) := utl_raw.cast_to_raw( 'EC' );
      return true;
    exception when value_error
      then
        p_pk_parameters.delete;
        return false;
    end;
    --
    function parse_pkcs8( p_key varchar2, p_pk_parameters out tp_pk_parameters )
    return boolean
    is
      l_key raw(32767);
      l_dummy raw(3999);
      l_ind pls_integer;
    begin
      p_pk_parameters.delete;
      l_key := base64_or_decrypt_pk( p_key, null, 'PRIVATE KEY' );
      if l_key is null
      then
        return false;
      end if;
      return parse_der_pkcs8( l_key, p_pk_parameters );
    end;
    --
    function parse_pkcs5v2( p_key varchar2, p_pw raw, p_pk_parameters out tp_pk_parameters )
    return boolean
    is
      l_rv boolean := false;
      l_key raw(32767);
      l_dummy raw(3999);
      l_oid raw(3999);
      l_ind pls_integer;
      l_len pls_integer;
      l_max_seq pls_integer;
      l_dk raw(3999);
      l_iv raw(3999);
      l_salt raw(3999);
      l_iteration_count pls_integer;
      l_keylength pls_integer;
      l_algo pls_integer;
      l_hash_type pls_integer;
      l_tt raw(3999);
      l_tmp raw(3999);
      l_pk_parameters tp_pk_parameters;
    begin
      l_key := base64_or_decrypt_pk( p_key, null, 'ENCRYPTED PRIVATE KEY' );
      if l_key is null
      then
        return false;
      end if;
      check_starting_sequence( l_key, l_ind );
      if utl_raw.substr( l_key, l_ind, 1 ) != c_SEQUENCE
      then
        debug_msg( 'pkcs#5 no sequence 1' );
        raise value_error;
      end if;
      l_len := get_len( l_key, l_ind );
      l_oid := get_oid( l_key, l_ind );
      debug_msg( 'pkcs#5 OID: ' || l_oid );
      if l_oid != '2A864886F70D01050D' -- 1.2.840.113549.1.5.13 pkcs5PBES2 (PKCS #5 v2.0)
      then
        debug_msg( 'pkcs#5 nopkcs5PBES2' );
        return false;
      end if;
      debug_msg( 'pkcs#5 pkcs5PBES2' );
      if utl_raw.substr( l_key, l_ind, 1 ) != c_SEQUENCE
      then
        debug_msg( 'pkcs#5 no sequence 2' );
        raise value_error;
      end if;
      l_len := get_len( l_key, l_ind );
      if utl_raw.substr( l_key, l_ind, 1 ) != c_SEQUENCE
      then
        debug_msg( 'pkcs#5 no sequence 3' );
        raise value_error;
      end if;
      l_len := get_len( l_key, l_ind );
      l_oid := get_oid( l_key, l_ind );
      if l_oid = '2A864886F70D01050C' -- 1.2.840.113549.1.5.12 pkcs5PBKDF2 (PKCS #5 v2.0)
      then
        if utl_raw.substr( l_key, l_ind, 1 ) != c_SEQUENCE
        then
          debug_msg( 'pkcs#5 no sequence 4' );
          raise value_error;
        end if;
        l_len := get_len( l_key, l_ind );
        l_max_seq := l_ind + l_len;
        l_salt := get_octect( l_key, l_ind, 'No Salt' );
        l_iteration_count := to_number( get_integer( l_key, l_ind, 'No iterationCount' ), 'xxxxxxxx' );
        if l_ind < l_max_seq and utl_raw.substr( l_key, l_ind, 1 ) = c_INTEGER
        then
          l_keylength := to_number( get_integer( l_key, l_ind ), 'xxxxxxxx' );
        end if;
        l_hash_type := HMAC_SH1;  -- default
        if l_ind < l_max_seq and utl_raw.substr( l_key, l_ind, 1 ) = c_OID
        then
          l_oid := get_oid( l_key, l_ind );
        elsif l_ind < l_max_seq and utl_raw.substr( l_key, l_ind, 1 ) = c_SEQUENCE
        then
          l_len := get_len( l_key, l_ind );
          l_oid := get_oid( l_key, l_ind, 'No HMAC' );
        end if;
        if l_oid = '2A864886F70D0209' -- 1.2.840.113549.2.9 hmacWithSHA256 (RSADSI digestAlgorithm)
        then
          l_hash_type := HMAC_SH256;
        elsif l_oid = '2A864886F70D020B' -- 1.2.840.113549.2.11 hmacWithSHA512 (RSADSI digestAlgorithm)
        then
          l_hash_type := HMAC_SH512;
        elsif l_oid = '2A864886F70D020A' -- 1.2.840.113549.2.10 hmacWithSHA384 (RSADSI digestAlgorithm)
        then
          raise value_error;
        elsif l_oid = '2A864886F70D0208' -- 1.2.840.113549.2.8 hmacWithSHA224 (RSADSI digestAlgorithm)
        then
          raise value_error;
        else
          raise value_error;
        end if;
        l_ind := l_max_seq;
        if utl_raw.substr( l_key, l_ind, 1 ) != c_SEQUENCE
        then
          debug_msg( 'pkcs#5 no sequence 4' );
          raise value_error;
        end if;
        l_len := get_len( l_key, l_ind );
        l_oid := get_oid( l_key, l_ind, 'No encryptionScheme OID' );
        l_iv := get_octect( l_key, l_ind, 'No IV' );
        if l_oid = '608648016503040102' -- 2.16.840.1.101.3.4.1.2 aes128-CBC (NIST Algorithm)
        then
          debug_msg( 'pkcs#5 aes128-CBC' );
          l_algo := dbms_crypto.ENCRYPT_AES128 + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_PKCS5;
          l_keylength := 16;
        elsif l_oid = '60864801650304012A' -- 2.16.840.1.101.3.4.1.42 aes256-CBC (NIST Algorithm)
        then
          debug_msg( 'pkcs#5 aes256-CBC' );
          l_algo := dbms_crypto.ENCRYPT_AES256 + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_PKCS5;
          l_keylength := 32;
        end if;
        if l_algo is null
        then
          raise value_error;
        end if;
        for i in 1 .. 5
        loop
          l_tmp := utl_raw.concat( l_salt, to_char( i, 'fm0xxxxxxx' ) );
          for c in 1 .. l_iteration_count
          loop
            l_tmp := dbms_crypto.mac( l_tmp, l_hash_type, p_pw );
            if c = 1
            then
              l_tt := l_tmp;
            else
              l_tt := utl_raw.bit_xor( l_tt, l_tmp );
            end if;
          end loop;
          l_dk := utl_raw.concat( l_dk, l_tt );
          exit when utl_raw.length( l_dk ) >= l_keylength;
        end loop;
        l_dk := utl_raw.substr( l_dk, 1, l_keylength );
        l_rv := parse_der_pkcs8( dbms_crypto.decrypt( get_octect( l_key, l_ind )
                                                    , l_algo
                                                    , l_dk
                                                    , l_iv
                                                    )
                                , p_pk_parameters
                                );
      end if;
      return l_rv;
    exception
      when value_error
      then
        p_pk_parameters.delete;
        error_msg( 'could not parse key: ' || l_key );
        return false;
    end;
    --
    function parse_OPENSSH_private_key( p_key varchar2, p_pw raw, p_pk_parameters out tp_pk_parameters )
    return boolean
    is
      l_rv boolean;
      l_vkey varchar2(32767);
      l_tmp raw(32767);
      l_idx number;
      l_len number;
      l_ciphername varchar2(32767);
      l_kdfname varchar2(32767);
      l_salt raw(100);
      l_rounds pls_integer;
      l_pk_bytes raw(32767);
      l_kdf raw(2048);
      l_key raw(2048);
      l_iv  raw(2048);
      l_iv_ctr number;
      l_keytype varchar2(32767);
      l_cnt pls_integer;
    begin
      if (  substr( p_key, 1, 25 ) != 'BEGIN OPENSSH PRIVATE KEY'
         or substr( p_key, -23 ) != 'END OPENSSH PRIVATE KEY'
         )
      then
        return false;
      end if;
      -- http://dnaeon.github.io/openssh-private-key-binary-format/
      debug_msg( 'openssh private key' );
      l_vkey := substr( p_key, 26, length( p_key ) - 48 );
      l_vkey := ltrim( l_vkey, '- ' || chr(10) || chr(13) );
      l_vkey := rtrim( l_vkey, '- ' || chr(10) || chr(13) );
      if substr( l_vkey, 1, 20 ) != 'b3BlbnNzaC1rZXktdjEA' -- openssh-key-v1
      then
        return false;
      end if;
      l_tmp := utl_encode.base64_decode( utl_raw.cast_to_raw( l_vkey ) );
      l_idx := 16;
      l_len := to_number( utl_raw.substr( l_tmp, l_idx, 4 ), 'xxxxxxxx' );
      l_idx := l_idx + 4;
      if l_len between 1 and 32767
      then
        l_ciphername := utl_raw.cast_to_varchar2( utl_raw.substr( l_tmp, l_idx, l_len ) );
      end if;
      if l_ciphername is null or l_ciphername not in ( 'none', 'aes256-ctr' )
      then
        return false;
      end if;
      l_idx := l_idx + l_len;
      l_len := to_number( utl_raw.substr( l_tmp, l_idx, 4 ), 'xxxxxxxx' );
      l_idx := l_idx + 4;
      if l_len between 1 and 32767
      then
        l_kdfname := utl_raw.cast_to_varchar2( utl_raw.substr( l_tmp, l_idx, l_len ) );
      end if;
      if l_kdfname is null or l_kdfname not in ( 'none', 'bcrypt' )
      then
        return false;
      end if;
      l_idx := l_idx + l_len;
      l_len := to_number( utl_raw.substr( l_tmp, l_idx, 4 ), 'xxxxxxxx' );
      l_idx := l_idx + 4;
      if l_len > 0 -- kdfoptions
      then
        l_len := to_number( utl_raw.substr( l_tmp, l_idx, 4 ), 'xxxxxxxx' );
        l_idx := l_idx + 4;
        l_salt := utl_raw.substr( l_tmp, l_idx, l_len );
        l_idx := l_idx + l_len;
        l_rounds := to_number( utl_raw.substr( l_tmp, l_idx, 4 ), 'xxxxxxxx' );
        l_idx := l_idx + 4;
      end if;
      l_len := to_number( utl_raw.substr( l_tmp, l_idx, 4 ), 'xxxxxxxx' );
      l_idx := l_idx + 4;          -- # keys
      l_len := to_number( utl_raw.substr( l_tmp, l_idx, 4 ), 'xxxxxxxx' );
      l_idx := l_idx + 4;
      l_idx := l_idx + l_len;  -- public keys
      l_len := to_number( utl_raw.substr( l_tmp, l_idx, 4 ), 'xxxxxxxx' );
      l_idx := l_idx + 4; -- skip length private keys
      debug_msg( 'kdfname: ' || l_kdfname );
      debug_msg( 'ciphername: ' || l_ciphername );
      if l_kdfname = 'bcrypt'
      then
        return false;
      end if;
      if l_ciphername = 'aes256-ctr'
      then
        l_iv_ctr := to_number( l_iv, rpad( 'X', 32, 'X' ) );
        for i in 0 .. l_len / 16 - 1
        loop
          l_pk_bytes := utl_raw.concat( l_pk_bytes
                                      , utl_raw.bit_xor( utl_raw.substr( l_tmp, l_idx + i * 16, 16 )
                                                       , dbms_crypto.encrypt( substr( to_char( l_iv_ctr, 'FM0XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' ), -32 )
                                                                            , dbms_crypto.ENCRYPT_AES + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_NONE
                                                                            , l_key
                                                                            )
                                                       )
                                      );
          l_iv_ctr := l_iv_ctr + 1;
          if l_iv_ctr > 340282366920938463463374607431768211455
          then
            l_iv_ctr := 0;
          end if;
        end loop;
      elsif l_ciphername = 'none'
      then
        l_pk_bytes := utl_raw.substr( l_tmp, l_idx );
      end if;
      if utl_raw.substr( l_pk_bytes, 1, 4 ) != utl_raw.substr( l_pk_bytes, 5, 4 )
      then
        return false;
      end if;
      l_idx := 9; -- skip random
      l_len := to_number( utl_raw.substr( l_pk_bytes, l_idx, 4 ), 'xxxxxxxx' );
      l_idx := l_idx + 4;
      if l_len between 1 and 3999
      then
         l_keytype := utl_raw.cast_to_varchar2( utl_raw.substr( l_pk_bytes, l_idx, l_len ) );
      end if;
      l_idx := l_idx + l_len;
      debug_msg( 'keytype: ' || l_keytype );
      if l_keytype = 'ssh-rsa'
      then
        l_cnt := 3;
      elsif l_keytype = 'ssh-dss'
      then
        l_cnt := 5;
      elsif l_keytype in ( 'ecdsa-sha2-nistp256'
                         , 'ecdsa-sha2-nistp384'
                         , 'ecdsa-sha2-nistp521'
                         )
      then
        l_cnt := 4;
      elsif l_keytype in ( 'ssh-ed25519', 'ssh-ed448' )
      then
        l_cnt := 2;
      end if;
      for i in 1 .. l_cnt
      loop
        l_len := to_number( utl_raw.substr( l_pk_bytes, l_idx, 4 ), 'xxxxxxxx' );
        l_idx := l_idx + 4;
        if l_len between 1 and 3999
        then
          p_pk_parameters( i ) := utl_raw.substr( l_pk_bytes, l_idx, l_len );
        else
          return false;
        end if;
        l_idx := l_idx + l_len;
      end loop;
      p_pk_parameters( l_cnt + 1 ) := utl_raw.cast_to_raw( l_keytype );
      l_rv := true;
      if l_keytype = 'ssh-rsa'
      then
        p_pk_parameters(0) := utl_raw.cast_to_raw( 'RSA' );
      elsif l_keytype in ( 'ecdsa-sha2-nistp256'
                         , 'ecdsa-sha2-nistp384'
                         , 'ecdsa-sha2-nistp521'
                         )
      then
        p_pk_parameters(0) := utl_raw.cast_to_raw( 'EC' );
      elsif l_keytype in ( 'ssh-ed25519', 'ssh-ed448' )
      then
        p_pk_parameters(0) := utl_raw.cast_to_raw( 'EDDSA' );
      elsif l_keytype = 'ssh-dss'
      then
        p_pk_parameters(0) := utl_raw.cast_to_raw( 'DSA' );
        l_rv := false;
      else
        l_rv := false;
      end if;
      return l_rv;
    exception
      when value_error
      then
        p_pk_parameters.delete;
        error_msg( 'could not parse key: ' || l_key );
        return false;
    end;
    --
  begin
    init_hmac_ids;
    l_key := rtrim( p_key, '- ' || chr(10) || chr(13) );
    l_key := ltrim( l_key, '- ' || chr(10) || chr(13) );
    l_pw := utl_i18n.string_to_raw( p_passphrase, 'AL32UTF8' );
    return parse_RSA_private_key( l_key, l_pw, p_pk_parameters )
        or parse_EC_private_key( l_key, l_pw, p_pk_parameters )
        or parse_DSA_private_key( l_key, l_pw, p_pk_parameters )
        or parse_OPENSSH_private_key( l_key, l_pw, p_pk_parameters )
        or parse_pkcs8( l_key, p_pk_parameters )
        or parse_pkcs5v2( l_key, utl_raw.cast_to_raw( p_passphrase ), p_pk_parameters );
  exception
    when value_error
    then
      p_pk_parameters.delete;
      return false;
  end;
  --
  function do_auth( p_user varchar2, p_pk_parameters tp_pk_parameters )
  return boolean
  is
    l_rv boolean;
    l_pk_OK boolean;
    l_idx pls_integer;
    l_buf raw(32767);
    l_buf2 raw(32767);
    --
    function write_pk( p_algo varchar2, p_blob raw, p_signature raw )
    return boolean
    is
      l_rv boolean := false;
      l_buf4 raw(32767);
    begin
      l_pk_OK := false;
      l_buf := SSH_MSG_USERAUTH_REQUEST;
      append_string( l_buf, utl_i18n.string_to_raw( p_user, 'AL32UTF8' ) );
      append_string( l_buf, utl_i18n.string_to_raw( 'ssh-connection', 'US7ASCII' ) );
      append_string( l_buf, utl_i18n.string_to_raw( 'publickey', 'US7ASCII' ) );
      append_boolean( l_buf, p_signature is not null );
      append_string( l_buf, utl_i18n.string_to_raw( p_algo, 'US7ASCII' ) );
      append_string( l_buf, p_blob );
      if p_signature is not null
      then
        append_string( l_buf, p_signature );
      end if;
      write_packet( l_buf );
      info_msg( 'try ' || p_algo || ' public key' );
      read_until( l_buf4, SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE, SSH_MSG_USERAUTH_PK_OK );
      case utl_raw.substr( l_buf4, 1, 1 )
        when SSH_MSG_USERAUTH_SUCCESS
        then
          info_msg( p_algo || ' public key OK' );
          l_rv := true;
        when SSH_MSG_USERAUTH_FAILURE
        then
          info_msg( p_algo || ' public key not OK' );
        when SSH_MSG_USERAUTH_PK_OK
        then
          info_msg( 'server accepts ' || p_algo || ' public key' );
          l_pk_OK := true;
          l_buf := utl_raw.overlay( '01'
                                  , l_buf
                                  , 37 + utl_raw.length( utl_i18n.string_to_raw( p_user, 'AL32UTF8' ) )
                                  , 1
                                  );
      end case;
      return l_rv;
    end;
    --
    function write_rsa_pk( p_hash_type pls_integer )
    return boolean
    is
      l_rv boolean;
      l_buf3 raw(3999);
      l_buf5 raw(3999);
      l_algo varchar2(100);
    begin
      if p_pk_parameters.count = 0
      then
        return false;
      end if;
      l_buf2 := null;
      l_algo := case p_hash_type
                  when HASH_SH256 then 'rsa-sha2-256'
                  when HASH_SH512 then 'rsa-sha2-512'
                  else 'ssh-rsa'
                end;
      append_string( l_buf2, utl_i18n.string_to_raw( l_algo, 'US7ASCII' ) );
      append_mpint( l_buf2, p_pk_parameters(2) );
      append_mpint( l_buf2, p_pk_parameters(1) );
      l_rv := write_pk( l_algo, l_buf2, null );
      if not l_pk_OK
      then
        return l_rv;
      end if;
      append_string( l_buf3, g_session_id );
      append_byte( l_buf3, l_buf );
      l_buf3 := powmod( utl_raw.concat( '01'
                                      , utl_raw.copies( 'FF'
                                                      , utl_raw.length( p_pk_parameters(1) )
                                                      - case p_hash_type
                                                          when HASH_SH256 then 54
                                                          when HASH_SH512 then 86
                                                          else 38
                                                        end
                                                      - case when utl_raw.substr( p_pk_parameters(1), 1, 1 ) = '00' then 1 else 0 end
                                                      )
                                      , case p_hash_type
                                          when HASH_SH256 then '003031300D060960864801650304020105000420' -- fixed ASN.1 value SHA256
                                          when HASH_SH512 then '003051300d060960864801650304020305000440' -- fixed ASN.1 value SHA512
                                          else '003021300906052B0E03021A05000414' -- fixed ASN.1 value SHA1
                                        end
                                      , dbms_crypto.hash( l_buf3, p_hash_type )
                                      )
                      , p_pk_parameters(3)
                      , p_pk_parameters(1)
                      );
      append_string( l_buf5, utl_i18n.string_to_raw( l_algo, 'US7ASCII' ) );
      append_string( l_buf5, l_buf3 );
      return write_pk( l_algo, l_buf2, l_buf5 );
    end;
    --
    function write_dsa_pk
    return boolean
    is
      l_rv boolean;
      l_k raw(3999);
      l_r raw(3999);
      l_s raw(3999);
      l_mq tp_mag;
      l_dummy tp_mag;
      l_idx pls_integer;
      l_buf3 raw(3999);
    begin
      l_buf2 := null;
      append_string( l_buf2, utl_i18n.string_to_raw( 'ssh-dss', 'US7ASCII' ) );
      append_mpint( l_buf2, p_pk_parameters(1) );
      append_mpint( l_buf2, p_pk_parameters(2) );
      append_mpint( l_buf2, p_pk_parameters(3) );
      append_mpint( l_buf2, p_pk_parameters(4) );
      l_rv := write_pk( 'ssh-dss', l_buf2, null );
      if not l_pk_OK
      then
        return l_rv;
      end if;
      loop
        l_k := dbms_crypto.randombytes( utl_raw.length( p_pk_parameters(2) ) );
        l_idx := utl_raw.compare( l_k, p_pk_parameters(2) );
        exit when utl_raw.substr( l_k, -3 ) != '000000' and utl_raw.substr( l_k, l_idx, 1 ) < utl_raw.substr( p_pk_parameters(2), l_idx, 1 );
      end loop;
      l_mq := mag( p_pk_parameters(2) );
      l_r := demag( xmod( mag( powmod( p_pk_parameters(3), l_k, p_pk_parameters(1) ) ), l_mq ) );
      append_string( l_buf3, g_session_id );
      append_byte( l_buf3, l_buf );
      l_dummy := mag( dbms_crypto.hash( l_buf3, HASH_SH1 ) );
      l_dummy := xmod( radd( l_dummy, xmod( rmul( mag( p_pk_parameters(5) ), mag( l_r ) ), l_mq ) ), l_mq );
      l_dummy := mulmod( l_dummy, powmod( mag( l_k ), nsub( l_mq, 2 ), l_mq ), l_mq );
      l_s := demag( l_dummy );
      l_s := utl_raw.overlay( l_s, utl_raw.copies( '00', 20 ), 21 - utl_raw.length( l_s ) );
      l_r := utl_raw.overlay( l_r, utl_raw.copies( '00', 20 ), 21 - utl_raw.length( l_r ) );
      l_buf3 := null;
      append_string( l_buf3, utl_i18n.string_to_raw( 'ssh-dss', 'US7ASCII' ) );
      append_string( l_buf3, utl_raw.concat( l_r, l_s ) );
      return write_pk( 'ssh-dss', l_buf2, l_buf3 );
    end;
    --
    function write_ec_pk
    return boolean
    is
      l_rv boolean;
      l_algo raw(100);
      l_buf3 raw(3999);
      l_buf5 raw(3999);
      l_r tp_mag;
      l_s tp_mag;
      l_inv tp_mag;
      l_xxx tp_mag;
      l_pb tp_ec_point;
      l_curve tp_ec_curve;
      l_hash_type pls_integer;
    begin
      if p_pk_parameters.count = 0
      then
        return false;
      end if;
      l_buf2 := null;
      l_algo := utl_raw.concat( '65636473612D736861322D', p_pk_parameters(1) ); -- ecdsa-sha2-
      append_string( l_buf2, l_algo );
      append_string( l_buf2, p_pk_parameters(1) );
      append_string( l_buf2, p_pk_parameters(2) );
      l_rv := write_pk( utl_i18n.raw_to_char( l_algo, 'US7ASCII' ), l_buf2, null );
      if not l_pk_OK
      then
        return false;
      end if;
      case p_pk_parameters(1)
        when hextoraw( '6E69737470323536' ) -- nistp256
        then
          l_hash_type := HASH_SH256;
        when hextoraw( '6E69737470333834' ) -- nistp384
        then
          l_hash_type := HASH_SH384;
        when hextoraw( '6E69737470353231' ) -- nistp521
        then
          l_hash_type := HASH_SH512;
        else
          return false;
      end case;
      get_named_curve( utl_raw.cast_to_varchar2( p_pk_parameters(1) ), l_curve );
      append_string( l_buf3, g_session_id );
      append_byte( l_buf3, l_buf );
      l_xxx := mag( dbms_crypto.randombytes( 4 ) );
      l_pb  := multiply_point( l_curve.generator, l_xxx, l_curve );
      l_r := xmod( l_pb.x, l_curve.group_order );
      l_inv := powmod( l_xxx, nsub( l_curve.group_order, 2 ), l_curve.group_order );
      l_s := mulmod( radd( mag( dbms_crypto.hash( l_buf3, l_hash_type ) )
                         , mulmod( mag( p_pk_parameters(3) )
                                 , l_r
                                 , l_curve.group_order
                                 )
                         )
                   , l_inv
                   , l_curve.group_order
                   );
      l_buf3 := null;
      append_string( l_buf3, demag( l_r ) );
      append_string( l_buf3, demag( l_s ) );
      append_string( l_buf5, l_algo );
      append_string( l_buf5, l_buf3 );
      return write_pk( utl_i18n.raw_to_char( l_algo, 'US7ASCII' ), l_buf2, l_buf5 );
    end;
    --
    function do_password
    return boolean
    is
    begin
      l_buf := SSH_MSG_USERAUTH_REQUEST;
      append_string( l_buf, coalesce( utl_i18n.string_to_raw( p_user, 'AL32UTF8' ), p_pk_parameters(2) ) );
      append_string( l_buf, utl_i18n.string_to_raw( 'ssh-connection', 'US7ASCII' ) );
      append_string( l_buf, utl_i18n.string_to_raw( 'password', 'US7ASCII' ) );
      append_boolean( l_buf, false );
      append_string( l_buf, p_pk_parameters(1) );
      write_packet( l_buf );
      read_until( l_buf, SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE );
      if utl_raw.substr( l_buf, 1, 1 ) = SSH_MSG_USERAUTH_SUCCESS
      then
        info_msg( 'connect with password' );
        return true;
      end if;
      return false;
    end;
  begin
    l_rv := false;
    l_buf := SSH_MSG_SERVICE_REQUEST;
    append_string( l_buf, utl_i18n.string_to_raw( 'ssh-userauth', 'US7ASCII' ) );
    write_packet( l_buf );
    read_until( l_buf, SSH_MSG_SERVICE_ACCEPT );
    info_msg( 'ssh-userauth accepted' );
    l_buf := SSH_MSG_USERAUTH_REQUEST;
    append_string( l_buf, utl_i18n.string_to_raw( p_user, 'AL32UTF8' ) );
    append_string( l_buf, utl_i18n.string_to_raw( 'ssh-connection', 'US7ASCII' ) );
    append_string( l_buf, utl_i18n.string_to_raw( 'none', 'US7ASCII' ) );
    write_packet( l_buf );
    read_until( l_buf, SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE );
    case utl_raw.substr( l_buf, 1, 1 )
      when SSH_MSG_USERAUTH_SUCCESS
      then
        info_msg( 'can connect with method none!' );
        l_rv := true;
      when SSH_MSG_USERAUTH_FAILURE
      then
        l_idx := 2;
        show_name_list( read_name_list( l_idx, l_buf ) );
    end case;
    if l_rv
    then
      return true;
    end if;
    return case utl_raw.cast_to_varchar2( ( p_pk_parameters( 0 ) ) )
             when 'RSA' then write_rsa_pk( HASH_SH1 )
                          or write_rsa_pk( HASH_SH256 )
                          or write_rsa_pk( HASH_SH512 )
             when 'password' then do_password
             when 'EC' then write_ec_pk
--                 when 'EDDSA' then write_eddsa_pk( l_pk_parameters )
             when 'DSA' then write_dsa_pk
           end;
  end;
  --
  procedure write_fxp_message( p_type raw, p_payload raw )
  is
    l_buf raw(32767);
  begin
    l_buf := SSH_MSG_CHANNEL_DATA;
    append_int32( l_buf, g_ssh_channel.server_channel );
    append_string( l_buf, utl_raw.concat( to_char( 1 + utl_raw.length( p_payload ), 'fm0XXXXXXX' )
                                        , p_type
                                        , p_payload
                                        )
                 );
    write_packet( l_buf );
  end;
--
  procedure read_fxp_message( p_buf in out raw, p_first boolean := true )
  is
    l_idx number;
    l_len number;
    l_channel number;
    l_buf raw(32767);
  begin
    read_until( l_buf, SSH_MSG_CHANNEL_DATA );
    l_idx := 2;
    get_int32( l_idx, l_buf, l_channel );
    if l_channel = g_ssh_channel.my_channel
    then
      get_string( l_idx, l_buf, p_buf );
      g_ssh_channel.cur_window_size := g_ssh_channel.cur_window_size - utl_raw.length( l_buf );
      if g_ssh_channel.cur_window_size < g_ssh_channel.max_window_size / 2
      then
        debug_msg( 'adjust window' );
        l_buf := SSH_MSG_CHANNEL_WINDOW_ADJUST;
        append_int32( l_buf, g_ssh_channel.server_channel );
        append_int32( l_buf, g_ssh_channel.max_window_size - g_ssh_channel.cur_window_size );
        write_packet( l_buf );
        g_ssh_channel.cur_window_size := g_ssh_channel.max_window_size;
      end if;
      if p_first
      then
        if utl_raw.substr( p_buf, 1, 1 ) != '00' -- a welcome message
        then
          read_fxp_message( p_buf );
        else
          l_idx := 1;
          get_int32( l_idx, p_buf, l_len );
          -- skip length attribute
          if utl_raw.length( p_buf ) > 4
          then
            p_buf := utl_raw.substr( p_buf, 5 );
          else
            p_buf := null;
          end if;
          while coalesce( utl_raw.length( p_buf ), 0 ) < l_len
          loop
            read_fxp_message( l_buf, false );
            p_buf := utl_raw.concat( p_buf, l_buf );
          end loop;
        end if;
      end if;
    else
      debug_msg( 'handle??? 2' );
      debug_msg( l_buf );
    end if;
  end;
  --
  function open_sftp
  return boolean
  is
    l_rv boolean;
    l_idx pls_integer;
    l_buf raw(32767);
    l_buf2 raw(32767);
    l_dummy number;
  begin
    g_ssh_channel.my_channel := 123;
    g_ssh_channel.max_window_size := 33538048;
    g_ssh_channel.cur_window_size := g_ssh_channel.max_window_size;
    g_ssh_channel.my_packet_size := 32400;
    l_rv := false;
    l_buf := SSH_MSG_CHANNEL_OPEN;
    append_string( l_buf, utl_i18n.string_to_raw( 'session', 'US7ASCII' ) );
    append_int32( l_buf, g_ssh_channel.my_channel );
    append_int32( l_buf, g_ssh_channel.max_window_size );
    append_int32( l_buf, g_ssh_channel.my_packet_size );
    write_packet( l_buf );
    read_until( l_buf, SSH_MSG_CHANNEL_OPEN_CONFIRM, SSH_MSG_CHANNEL_OPEN_FAILURE );
    if utl_raw.substr( l_buf, 1, 1 ) = SSH_MSG_CHANNEL_OPEN_FAILURE
    then
      l_idx := 2;
      get_int32( l_idx, l_buf, l_dummy ); -- recipient channel
      get_int32( l_idx, l_buf, l_dummy ); -- reason code
      get_string( l_idx, l_buf, l_buf2 );
    else -- SSH_MSG_CHANNEL_OPEN_CONFIRM
      l_idx := 2;
      get_int32( l_idx, l_buf, l_dummy );
      get_int32( l_idx, l_buf, g_ssh_channel.server_channel );
      get_int32( l_idx, l_buf, l_dummy );
      get_int32( l_idx, l_buf, g_ssh_channel.server_packet_size );
      l_buf := SSH_MSG_CHANNEL_REQUEST;
      append_int32( l_buf, g_ssh_channel.server_channel );
      append_string( l_buf, utl_i18n.string_to_raw( 'subsystem', 'US7ASCII' ) );
      append_boolean( l_buf, true );
      append_string( l_buf, utl_i18n.string_to_raw( 'sftp', 'US7ASCII' ) );
      write_packet( l_buf );
      read_until( l_buf, SSH_MSG_CHANNEL_SUCCESS, SSH_MSG_CHANNEL_FAILURE );
      if utl_raw.substr( l_buf, 1, 1 ) = SSH_MSG_CHANNEL_FAILURE
      then
        l_buf := SSH_MSG_CHANNEL_CLOSE;
        append_int32( l_buf, g_ssh_channel.server_channel );
        write_packet( l_buf );
      else -- SSH_MSG_CHANNEL_SUCCESS
        write_fxp_message( SSH_FXP_INIT, '00000003' );
        loop
          read_fxp_message( l_buf );
          if utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_VERSION
          then
            l_idx := 2;
            get_int32( l_idx, l_buf, l_dummy );
            if l_dummy = 3
            then
              info_msg( 'sftp openend, server version: ' || l_dummy );
              l_rv := true;
            else
              error_msg( 'sftp not openend, server version: ' || l_dummy || ' not supported' );
              l_rv := false;
            end if;
            exit;
          end if;
        end loop;
      end if;
    end if;
    return l_rv;
  end;
  --
  function get_real_path( p_path varchar2 )
  return varchar2
  is
    l_dummy number;
    l_fxp_id number;
    l_idx pls_integer;
    l_buf raw(32767);
    l_buf2 raw(32767);
  begin
    l_fxp_id := 240;
    append_int32( l_buf, l_fxp_id );
    append_string( l_buf, utl_i18n.string_to_raw( p_path, 'AL32UTF8' ) );
    write_fxp_message( SSH_FXP_REALPATH, l_buf );
    loop
      read_fxp_message( l_buf );
      if utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_NAME
      then
        l_idx := 2;
        get_int32( l_idx, l_buf, l_dummy );
        -- check l_dummy = l_fxp_id?
        get_int32( l_idx, l_buf, l_dummy );
        if l_dummy = 1
        then
          get_string( l_idx, l_buf, l_buf2 );
        end if;
        exit;
      elsif utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS
      then
        l_idx := 2;
        get_int32( l_idx, l_buf, l_dummy );
        -- check l_dummy = l_fxp_id?
        get_int32( l_idx, l_buf, l_dummy );
        -- error/status code
        debug_msg( 'SSH_FXP_REALPATH status code ' || l_dummy );
        exit;
      end if;
    end loop;
    return utl_i18n.raw_to_char( l_buf2, 'AL32UTF8' );
  end;
  --
  function pwd
  return varchar2
  is
  begin
    return get_real_path( '.' );
  end;
  --
  function get_file( i_path varchar2, i_file in out nocopy blob )
  return boolean
  is
    l_dummy number;
    l_fxp_id number;
    l_idx pls_integer;
    l_fxp_handle raw(256);
    l_buf raw(32767);
    l_buf2 raw(32767);
    l_rv boolean;
    l_len number := g_ssh_channel.my_packet_size - 16;
    l_file_offset number;
  begin
    l_rv := false;
    l_buf := null;
    l_fxp_id := 245;
    append_int32( l_buf, l_fxp_id );
    append_string( l_buf, utl_i18n.string_to_raw( i_path, 'AL32UTF8' ) );
    append_int32( l_buf, SSH_FXF_READ );
    append_int32( l_buf, 0 );
    write_fxp_message( SSH_FXP_OPEN, l_buf );
    loop
      read_fxp_message( l_buf );
      if utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS
      then
        debug_msg( 'get_file: not opened' );
        l_idx := 2;
        get_int32( l_idx, l_buf, l_dummy ); -- id
        get_int32( l_idx, l_buf, l_dummy ); -- reason code
        get_string( l_idx, l_buf, l_buf2 );
        debug_msg( utl_i18n.raw_to_char( l_buf2, 'AL32UTF8' ) );
        exit;
      elsif utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_HANDLE
      then
        debug_msg( 'get_file: opened' );
        if i_file is null
        then
          dbms_lob.createtemporary( i_file, true );
        else
          if    dbms_lob.istemporary ( i_file ) = 0
            and dbms_lob.isopen( i_file ) = 0
          then
            dbms_lob.open( i_file, dbms_lob.lob_readwrite );
          end if;
          dbms_lob.trim( i_file, 0 );
        end if;
        l_idx := 2;
        get_int32( l_idx, l_buf, l_dummy );
        get_string( l_idx, l_buf, l_fxp_handle );
        l_file_offset := 0;
        loop
          l_buf := null;
          l_fxp_id := 252;
          append_int32( l_buf, l_fxp_id );
          append_string( l_buf, l_fxp_handle );
          append_int64( l_buf, l_file_offset );
          append_int32( l_buf, l_len );
          l_file_offset := l_file_offset + l_len;
          write_fxp_message( SSH_FXP_READ, l_buf );
          read_fxp_message( l_buf );
          exit when utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS;
          if utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_DATA
          then
            l_idx := 2;
            get_int32( l_idx, l_buf, l_dummy );
            get_string( l_idx, l_buf, l_buf2 );
            dbms_lob.writeappend( i_file, utl_raw.length( l_buf2 ), l_buf2 );
          end if;
        end loop;
        --
        debug_msg( 'get_file: read done' );
        l_buf := null;
        l_fxp_id := 253;
        append_int32( l_buf, l_fxp_id );
        append_string( l_buf, l_fxp_handle );
        write_fxp_message( SSH_FXP_CLOSE, l_buf );
        loop
          read_fxp_message( l_buf );
          exit when utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS;
        end loop;
        debug_msg( 'get_file: closed' );
        if dbms_lob.istemporary ( i_file ) = 0
        then
          dbms_lob.close( i_file );
        end if;
        l_rv := true;
        exit;
      end if;
    end loop;
    return l_rv;
  end;
  --
  procedure get_file( i_path varchar2, i_file in out nocopy blob )
  is
    l_rv boolean;
  begin
    l_rv := get_file( i_path, i_file );
  end;
  --
  function get_file( i_path varchar2, i_directory varchar2, i_filename varchar2 )
  return boolean
  is
    l_file blob;
    l_rv boolean;
    l_fh utl_file.file_type;
    l_len pls_integer := 32767;
  begin
    l_rv := get_file( i_path, l_file );
    l_fh := utl_file.fopen( i_directory, i_filename, 'wb' );
    for i in 0 .. trunc( ( dbms_lob.getlength( l_file ) - 1 ) / l_len )
    loop
      utl_file.put_raw( l_fh
                      , dbms_lob.substr( l_file
                                       , l_len
                                       , i * l_len + 1
                                       )
                      );
    end loop;
    utl_file.fflush( l_fh );
    utl_file.fclose( l_fh );
    dbms_lob.freetemporary( l_file );
    return l_rv;
  end;
  --
  procedure get_file( i_path varchar2, i_directory varchar2, i_filename varchar2 )
  is
    l_rv boolean;
  begin
    l_rv := get_file( i_path, i_directory, i_filename );
  end;
  --
  function put_file( i_path varchar2, i_file blob )
  return boolean
  is
    l_dummy number;
    l_reason number;
    l_fxp_id number;
    l_idx pls_integer;
    l_fxp_handle raw(256);
    l_buf raw(32767);
    l_buf2 raw(32767);
    l_rv boolean;
    l_len number := least( g_ssh_channel.server_packet_size, 32400 );
    l_file_offset number;
  begin
    l_rv := false;
    l_buf := null;
    l_fxp_id := 245;
    append_int32( l_buf, l_fxp_id );
    append_string( l_buf, utl_i18n.string_to_raw( i_path, 'AL32UTF8' ) );
    append_int32( l_buf, SSH_FXF_WRITE + SSH_FXF_CREAT + SSH_FXF_TRUNC );
    append_int32( l_buf, 0 );
    write_fxp_message( SSH_FXP_OPEN, l_buf );
    loop
      read_fxp_message( l_buf );
      if utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS
      then
        debug_msg( 'put_file: not opened' );
        l_idx := 2;
        get_int32( l_idx, l_buf, l_dummy ); -- id
        get_int32( l_idx, l_buf, l_dummy ); -- reason code
        get_string( l_idx, l_buf, l_buf2 );
        debug_msg( utl_i18n.raw_to_char( l_buf2, 'AL32UTF8' ) );
        exit;
      elsif utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_HANDLE
      then
        debug_msg( 'put_file: opened' );
        l_idx := 2;
        get_int32( l_idx, l_buf, l_dummy );
        get_string( l_idx, l_buf, l_fxp_handle );
        l_file_offset := 0;
        for i in 1 .. ceil( dbms_lob.getlength( i_file ) / l_len )
        loop
          l_buf := null;
          l_fxp_id := 252;
          append_int32( l_buf, l_fxp_id );
          append_string( l_buf, l_fxp_handle );
          append_int64( l_buf, l_file_offset );
          append_string( l_buf, dbms_lob.substr( i_file, l_len, l_file_offset + 1 ) );
          l_file_offset := l_file_offset + l_len;
          write_fxp_message( SSH_FXP_WRITE, l_buf );
          loop
            read_fxp_message( l_buf );
            if utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS
            then
              l_idx := 2;
              get_int32( l_idx, l_buf, l_dummy );
              get_int32( l_idx, l_buf, l_reason ); -- reason code
              if l_reason != SSH_FX_OK
              then
                get_string( l_idx, l_buf, l_buf2 );
                debug_msg( utl_i18n.raw_to_char( l_buf2, 'AL32UTF8' ) );
              end if;
              exit;
            end if;
          end loop;
          exit when l_reason != SSH_FX_OK;
        end loop;
        --
        debug_msg( 'put_file: done' );
        l_buf := null;
        l_fxp_id := 253;
        append_int32( l_buf, l_fxp_id );
        append_string( l_buf, l_fxp_handle );
        write_fxp_message( SSH_FXP_CLOSE, l_buf );
        loop
          read_fxp_message( l_buf );
          exit when utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS;
        end loop;
        debug_msg( 'put_file: closed' );
        l_rv := true;
        exit;
      end if;
    end loop;
    return l_rv;
  end;
  --
  procedure put_file( i_path varchar2, i_file blob )
  is
    l_rv boolean;
  begin
    l_rv := put_file( i_path, i_file );
  end;
  --
  function put_file( i_path varchar2, i_directory varchar2, i_filename varchar2 )
  return boolean
  is
    l_bfile bfile;
    l_file blob;
    l_dest_offset integer := 1;
    l_src_offset integer := 1;
    l_rv boolean;
  begin
    dbms_lob.createtemporary( l_file, true );
    l_bfile := bfilename( i_directory, i_filename );
    dbms_lob.fileopen( l_bfile, dbms_lob.file_readonly );
    dbms_lob.loadblobfromfile
      ( dest_lob => l_file
      , src_bfile => l_bfile
      , amount => dbms_lob.lobmaxsize
      , dest_offset => l_dest_offset
      , src_offset => l_src_offset
      );
    l_rv := put_file( i_path => i_path, i_file => l_file );
    dbms_lob.freetemporary( l_file );
    dbms_lob.fileclose(l_bfile);
    return l_rv;
  end;
  --
  procedure put_file( i_path varchar2, i_directory varchar2, i_filename varchar2 )
  is
    l_rv boolean;
  begin
    l_rv := put_file( i_path, i_directory, i_filename );
  end;
  --
  function read_dir( i_path varchar2 )
  return tp_dir_listing
  is
    l_cnt number;
    l_flags number;
    l_dummy number;
    l_fxp_id number;
    l_idx pls_integer;
    l_fxp_handle raw(256);
    l_buf raw(32767);
    l_buf2 raw(32767);
    l_dir_line tp_dir_line;
    l_dir_listing tp_dir_listing;
  begin
    l_buf := null;
    l_fxp_id := 254;
    append_int32( l_buf, l_fxp_id );
    append_string( l_buf, utl_i18n.string_to_raw( i_path, 'AL32UTF8' ) );
    write_fxp_message( SSH_FXP_OPENDIR, l_buf );
    loop
      read_fxp_message( l_buf );
      if utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS
      then
        debug_msg( 'read dir: not opened' );
        l_idx := 2;
        get_int32( l_idx, l_buf, l_dummy ); -- id
        get_int32( l_idx, l_buf, l_dummy ); -- reason code
        get_string( l_idx, l_buf, l_buf2 );
        debug_msg( utl_i18n.raw_to_char( l_buf2, 'AL32UTF8' ) );
        exit;
      elsif utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_HANDLE
      then
        debug_msg( 'read dir: opened' );
        l_idx := 2;
        get_int32( l_idx, l_buf, l_dummy );
        get_string( l_idx, l_buf, l_fxp_handle );
        --
        loop
          l_buf := null;
          l_fxp_id := 252;
          append_int32( l_buf, l_fxp_id );
          append_string( l_buf, l_fxp_handle );
          write_fxp_message( SSH_FXP_READDIR, l_buf );
          loop
            read_fxp_message( l_buf );
            exit when utl_raw.substr( l_buf, 1, 1 ) in ( SSH_FXP_STATUS, SSH_FXP_NAME );
          end loop;
          debug_msg( 'readdir' );
          exit when utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS;
          l_idx := 2;
          get_int32( l_idx, l_buf, l_dummy ); -- fxp_id
          get_int32( l_idx, l_buf, l_dummy ); -- count
          for i in 1 .. l_dummy
          loop
            l_dir_line := null;
            get_string( l_idx, l_buf, l_buf2 );
            l_dir_line.file_name := utl_raw.cast_to_varchar2( l_buf2 );
            get_string( l_idx, l_buf, l_buf2 );
            l_dir_line.long_name := utl_raw.cast_to_varchar2( l_buf2 );
            get_int32( l_idx, l_buf, l_flags );
            if bitand( l_flags, SSH_FILEXFER_ATTR_SIZE ) = SSH_FILEXFER_ATTR_SIZE
            then
              get_int64( l_idx, l_buf, l_dir_line.file_size );
            end if;
            if bitand( l_flags, SSH_FILEXFER_ATTR_UIDGID ) = SSH_FILEXFER_ATTR_UIDGID
            then
              get_int32( l_idx, l_buf, l_dir_line.uid );
              get_int32( l_idx, l_buf, l_dir_line.gid );
            end if;
            if bitand( l_flags, SSH_FILEXFER_ATTR_PERMISSIONS ) = SSH_FILEXFER_ATTR_PERMISSIONS
            then
              get_int32( l_idx, l_buf, l_dir_line.perm );
              l_dir_line.is_directory := bitand( l_dir_line.perm, S_IFDIR ) = S_IFDIR;
            else
              l_dir_line.is_directory := utl_raw.substr( l_buf2, 1, 1 ) = '64'; -- d
            end if;
            if bitand( l_flags, SSH_FILEXFER_ATTR_ACMODTIME ) = SSH_FILEXFER_ATTR_ACMODTIME
            then
              get_int32( l_idx, l_buf, l_dummy );
              l_dir_line.atime := to_date( '01-01-1970', 'dd-mm-yyyy' ) + numtodsinterval( l_dummy, 'SECOND' );
              get_int32( l_idx, l_buf, l_dummy );
              l_dir_line.mtime := to_date( '01-01-1970', 'dd-mm-yyyy' ) + numtodsinterval( l_dummy, 'SECOND' );
            end if;
            if bitand( l_flags, SSH_FILEXFER_ATTR_EXTENDED ) = SSH_FILEXFER_ATTR_EXTENDED
            then
              get_int32( l_idx, l_buf, l_cnt );
              for c in 1 .. l_cnt
              loop
                get_string( l_idx, l_buf, l_buf2 );
                get_string( l_idx, l_buf, l_buf2 );
              end loop;
            end if;
            l_dir_listing( l_dir_listing.count + 1 ) := l_dir_line;
          end loop;
        end loop;
        --
        l_buf := null;
        l_fxp_id := 253;
        append_int32( l_buf, l_fxp_id );
        append_string( l_buf, l_fxp_handle );
        write_fxp_message( SSH_FXP_CLOSE, l_buf );
        loop
          read_fxp_message( l_buf );
          exit when utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS;
        end loop;
        debug_msg( 'read dir: closed' );
        exit;
      end if;
    end loop;
    return l_dir_listing;
  end;
  --
  function path_exists( i_path varchar2, i_check_for_dir boolean := null )
  return boolean
  is
    l_dummy number;
    l_fxp_id number;
    l_idx pls_integer;
    l_buf raw(32767);
    l_buf2 raw(32767);
    l_flags number;
    l_is_dir boolean;
    l_rv boolean;
  begin
    l_rv := false;
    l_buf := null;
    l_fxp_id := 241;
    append_int32( l_buf, l_fxp_id );
    append_string( l_buf, utl_i18n.string_to_raw( i_path, 'AL32UTF8' ) );
    append_int32( l_buf, 0 );
    write_fxp_message( SSH_FXP_LSTAT, l_buf );
    loop
      read_fxp_message( l_buf );
      if utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_ATTRS
      then
        l_idx := 2;
        get_int32( l_idx, l_buf, l_flags );
        get_int32( l_idx, l_buf, l_flags );
        if bitand( l_flags, SSH_FILEXFER_ATTR_SIZE ) = SSH_FILEXFER_ATTR_SIZE
        then
          get_int64( l_idx, l_buf, l_dummy );
        end if;
        if bitand( l_flags, SSH_FILEXFER_ATTR_UIDGID ) = SSH_FILEXFER_ATTR_UIDGID
        then
          get_int32( l_idx, l_buf, l_dummy );
          get_int32( l_idx, l_buf, l_dummy );
        end if;
        if bitand( l_flags, SSH_FILEXFER_ATTR_PERMISSIONS ) = SSH_FILEXFER_ATTR_PERMISSIONS
        then
          get_int32( l_idx, l_buf, l_dummy );
          l_is_dir := bitand( l_dummy, S_IFDIR ) = S_IFDIR;
        else
          l_is_dir := utl_raw.substr( l_buf2, 1, 1 ) = '64'; -- d
        end if;
        l_rv := i_check_for_dir is null or l_is_dir = i_check_for_dir;
        if l_is_dir
        then
          debug_msg( 'path_exists: found directory' );
        else
          debug_msg( 'path_exists: found file' );
        end if;
        exit;
      elsif utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS
      then
        debug_msg( 'path_exists: not found' );
        l_idx := 2;
        get_int32( l_idx, l_buf, l_dummy ); -- id
        get_int32( l_idx, l_buf, l_dummy ); -- reason code
        get_string( l_idx, l_buf, l_buf2 );
        debug_msg( utl_i18n.raw_to_char( l_buf2, 'AL32UTF8' ) );
        exit;
      end if;
    end loop;
    return l_rv;
  end;
  --
  function file_exists( i_path varchar2 )
  return boolean
  is
  begin
    return path_exists( i_path, false );
  end;
  --
  function dir_exists( i_path varchar2, i_check_for_dir boolean := null )
  return boolean
  is
  begin
    return path_exists( i_path, true );
  end;
  --
  function remove_file( i_filename varchar2 )
  return boolean
  is
    l_dummy number;
    l_fxp_id number;
    l_idx pls_integer;
    l_buf raw(32767);
    l_buf2 raw(32767);
    l_rv boolean;
  begin
    l_rv := false;
    l_buf := null;
    l_fxp_id := 244;
    append_int32( l_buf, l_fxp_id );
    append_string( l_buf, utl_i18n.string_to_raw( i_filename, 'AL32UTF8' ) );
    write_fxp_message( SSH_FXP_REMOVE, l_buf );
    loop
      read_fxp_message( l_buf );
      if utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS
      then
        l_idx := 2;
        get_int32( l_idx, l_buf, l_dummy ); -- id
        get_int32( l_idx, l_buf, l_dummy ); -- reason code
        if l_dummy = SSH_FX_OK
        then
          l_rv := true;
          debug_msg( 'file removed' );
        else
          get_string( l_idx, l_buf, l_buf2 );
          debug_msg( 'file not removed. ' || utl_i18n.raw_to_char( l_buf2, 'AL32UTF8' ) );
        end if;
        exit;
      end if;
    end loop;
    return l_rv;
  end;
  --
  function remove_directory( i_path varchar2 )
  return boolean
  is
    l_dummy number;
    l_fxp_id number;
    l_idx pls_integer;
    l_buf raw(32767);
    l_buf2 raw(32767);
    l_rv boolean;
  begin
    l_rv := false;
    l_buf := null;
    l_fxp_id := 246;
    append_int32( l_buf, l_fxp_id );
    append_string( l_buf, utl_i18n.string_to_raw( i_path, 'AL32UTF8' ) );
    write_fxp_message( SSH_FXP_RMDIR, l_buf );
    loop
      read_fxp_message( l_buf );
      if utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS
      then
        l_idx := 2;
        get_int32( l_idx, l_buf, l_dummy ); -- id
        get_int32( l_idx, l_buf, l_dummy ); -- reason code
        if l_dummy = SSH_FX_OK
        then
          l_rv := true;
          debug_msg( 'directory removed' );
        else
          get_string( l_idx, l_buf, l_buf2 );
          debug_msg( 'directory not removed. ' || utl_i18n.raw_to_char( l_buf2, 'AL32UTF8' ) );
        end if;
        exit;
      end if;
    end loop;
    return l_rv;
  end;
  --
  function create_directory( i_path varchar2 )
  return boolean
  is
    l_dummy number;
    l_fxp_id number;
    l_idx pls_integer;
    l_buf raw(32767);
    l_buf2 raw(32767);
    l_rv boolean;
  begin
    l_rv := false;
    l_buf := null;
    l_fxp_id := 238;
    append_int32( l_buf, l_fxp_id );
    append_string( l_buf, utl_i18n.string_to_raw( i_path, 'AL32UTF8' ) );
    append_int32( l_buf, 0 );
    write_fxp_message( SSH_FXP_MKDIR, l_buf );
    loop
      read_fxp_message( l_buf );
      if utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS
      then
        l_idx := 2;
        get_int32( l_idx, l_buf, l_dummy ); -- id
        get_int32( l_idx, l_buf, l_dummy ); -- reason code
        if l_dummy = SSH_FX_OK
        then
          l_rv := true;
          debug_msg( 'directory created' );
        else
          get_string( l_idx, l_buf, l_buf2 );
          debug_msg( 'directory not removed. ' || utl_i18n.raw_to_char( l_buf2, 'AL32UTF8' ) );
        end if;
        exit;
      end if;
    end loop;
    return l_rv;
  end;
  --
  function rename_path( i_old_path varchar2, i_new_path varchar2, i_overwrite boolean := true )
  return boolean
  is
    l_dummy number;
    l_fxp_id number;
    l_idx pls_integer;
    l_buf raw(32767);
    l_buf2 raw(32767);
    l_rv boolean;
  begin
    l_rv := false;
    l_buf := null;
    l_fxp_id := 248;
    append_int32( l_buf, l_fxp_id );
    append_string( l_buf, utl_i18n.string_to_raw( i_old_path, 'AL32UTF8' ) );
    append_string( l_buf, utl_i18n.string_to_raw( i_new_path, 'AL32UTF8' ) );
    write_fxp_message( SSH_FXP_RENAME, l_buf );
    loop
      read_fxp_message( l_buf );
      if utl_raw.substr( l_buf, 1, 1 ) = SSH_FXP_STATUS
      then
        l_idx := 2;
        get_int32( l_idx, l_buf, l_dummy ); -- id
        get_int32( l_idx, l_buf, l_dummy ); -- reason code
        if l_dummy = SSH_FX_OK
        then
          l_rv := true;
          debug_msg( 'path renamed' );
        elsif (   i_overwrite
              and l_dummy = SSH_FX_FILE_ALREADY_EXISTS
              and (  remove_file( i_new_path )
                  or remove_directory( i_new_path )
                  )
              )
        then
          -- overwrite as attribute is introduced in version 6
          debug_msg( 'new_path first removed' );
          l_rv := rename_path( i_old_path, i_new_path );
        else
          get_string( l_idx, l_buf, l_buf2 );
          debug_msg( 'path not renamed. ' || utl_i18n.raw_to_char( l_buf2, 'AL32UTF8' ) );
        end if;
        exit;
      end if;
    end loop;
    return l_rv;
  end;
  --
  procedure login( i_user varchar2, i_password varchar2 := null, i_priv_key varchar2 := null, i_passphrase varchar2 := null, i_log_level pls_integer := null )
  is
    l_prev_log_level pls_integer := g_log_level;
    l_pk_parameters tp_pk_parameters;
  begin
    g_log_level := nvl( i_log_level, g_log_level );
    if i_password is not null
    then
      l_pk_parameters( 0 ) := utl_raw.cast_to_raw( 'password' );
      l_pk_parameters(1) := utl_i18n.string_to_raw( i_password, 'AL32UTF8' );
      l_pk_parameters(2) := utl_i18n.string_to_raw( i_user, 'AL32UTF8' );
    end if;
    if (  i_password is not null
       or parse_private_key( i_priv_key , i_passphrase, l_pk_parameters )
       )
       and do_auth( i_user, l_pk_parameters )
    then
      info_msg( 'logged in' );
      if open_sftp
      then
        info_msg( 'sftp open' );
      else
        raise_application_error( -20031, 'Could not start sftp subsystem.' );
      end if;
    else
      raise_application_error( -20030, 'Could not login.' );
    end if;
    g_log_level := l_prev_log_level;
  exception
    when others then
      g_log_level := l_prev_log_level;
      raise;
  end;
  --
  procedure open_connection
    ( p_host varchar2
    , p_port pls_integer
    , p_fingerprint varchar2
    , p_trust boolean
    , i_excluded_kex_algos   varchar2 := null
    , i_preferred_kex_algos  varchar2 := null
    , i_excluded_encr_algos  varchar2 := null
    , i_preferred_encr_algos varchar2 := null
    , i_excluded_pkey_algos  varchar2 := null
    , i_preferred_pkey_algos varchar2 := null
    )
  is
    l_buf raw(32767);
  begin
    if setup_connection( p_host, p_port )
    then
      info_msg( utl_raw.cast_to_varchar2( V_S ) );
      -- reset globals
      g_seqn_c := 0;
      g_seqn_s := 0;
      g_encr_algo_c  := null;
      g_encr_algo_s  := null;
      g_mac_algo_c   := null;
      g_mac_algo_s   := null;
      g_compr_algo_c := null;
      g_compr_algo_s := null;
      g_session_id   := null;
      my_globals := null;
      my_globals.excluded_kex_algos   := i_excluded_kex_algos;
      my_globals.preferred_kex_algos  := i_preferred_kex_algos;
      my_globals.excluded_encr_algos  := i_excluded_encr_algos;
      my_globals.preferred_encr_algos := i_preferred_encr_algos;
      my_globals.excluded_pkey_algos  := i_excluded_pkey_algos;
      my_globals.preferred_pkey_algos := i_preferred_pkey_algos;
      init_hmac_ids;
      --
      read_until( l_buf, SSH_MSG_KEXINIT );
      handle_kex( l_buf, p_fingerprint, p_trust );
    end if;
  end;
  --
  procedure open_connection
    ( i_host varchar2
    , i_port pls_integer := 22
    , i_excluded_kex_algos   varchar2 := null
    , i_preferred_kex_algos  varchar2 := null
    , i_excluded_encr_algos  varchar2 := null
    , i_preferred_encr_algos varchar2 := null
    , i_excluded_pkey_algos  varchar2 := null
    , i_preferred_pkey_algos varchar2 := null
    )
  is
  begin
    open_connection
      ( i_host
      , i_port
      , null
      , null
      , i_excluded_kex_algos
      , i_preferred_kex_algos
      , i_excluded_encr_algos
      , i_preferred_encr_algos
      , i_excluded_pkey_algos
      , i_preferred_pkey_algos
      );
  end;
  --
  procedure open_connection
    ( i_host varchar2
    , i_trust_server boolean
    , i_port pls_integer := 22
    , i_excluded_kex_algos   varchar2 := null
    , i_preferred_kex_algos  varchar2 := null
    , i_excluded_encr_algos  varchar2 := null
    , i_preferred_encr_algos varchar2 := null
    , i_excluded_pkey_algos  varchar2 := null
    , i_preferred_pkey_algos varchar2 := null
    )
  is
  begin
    open_connection
      ( i_host
      , i_port
      , null
      , i_trust_server
      , i_excluded_kex_algos
      , i_preferred_kex_algos
      , i_excluded_encr_algos
      , i_preferred_encr_algos
      , i_excluded_pkey_algos
      , i_preferred_pkey_algos
      );
  end;
  --
  procedure open_connection
    ( i_host varchar2
    , i_fingerprint varchar2
    , i_port pls_integer := 22
    , i_excluded_kex_algos   varchar2 := null
    , i_preferred_kex_algos  varchar2 := null
    , i_excluded_encr_algos  varchar2 := null
    , i_preferred_encr_algos varchar2 := null
    , i_excluded_pkey_algos  varchar2 := null
    , i_preferred_pkey_algos varchar2 := null
    )
  is
  begin
    open_connection
      ( i_host
      , i_port
      , i_fingerprint
      , null
      , i_excluded_kex_algos
      , i_preferred_kex_algos
      , i_excluded_encr_algos
      , i_preferred_encr_algos
      , i_excluded_pkey_algos
      , i_preferred_pkey_algos
      );
  end;
  --
  procedure close_connection
  is
    l_buf raw(32767);
  begin
    if g_ssh_channel.server_channel is not null
    then
      l_buf := SSH_MSG_CHANNEL_CLOSE;
      append_int32( l_buf, g_ssh_channel.server_channel );
      write_packet( l_buf );
      -- a lot of servers don't handle this according to specs and don't send this message
      begin
        read_until( l_buf, SSH_MSG_CHANNEL_CLOSE );
      exception when others then null;
      end;
      g_ssh_channel.server_channel := null;
    end if;
    if g_con.remote_host is not null
    then
      utl_tcp.close_connection( g_con );
      g_con.remote_host := null;
    end if;
    info_msg( 'everything closed' );
  end;
  --
  procedure set_log_level( i_level pls_integer )
  is
  begin
    g_log_level := i_level;
  end;
  --
  function decrypt_pkcs5( p_content raw, p_pw raw )
  return raw
  is
    l_ind pls_integer;
    l_len pls_integer;
    l_ind_encr pls_integer;
    l_max_seq pls_integer;
    l_oid raw(3999);
    l_dk raw(3999);
    l_iv raw(3999);
    l_salt raw(3999);
    l_iteration_count pls_integer;
    l_keylength pls_integer;
    l_algo pls_integer;
    l_hash_type pls_integer;
    l_tt raw(3999);
    l_tmp raw(3999);
  begin
    l_ind := 1;
    check_tag( p_content, l_ind, c_SEQUENCE, 'decrypt pkcs#5v2: does not start with sequence' );
    l_len := get_len( p_content, l_ind );
    l_ind_encr := l_ind + l_len;
    check_and_skip_tag( p_content, l_ind, c_SEQUENCE, 'decrypt pkcs#5v2: no sequence' );
    l_oid := get_oid( p_content, l_ind, 'decrypt pkcs#5v2: no key derivation OID' );
    if l_oid != '2A864886F70D01050C' -- 1.2.840.113549.1.5.12 pkcs5PBKDF2 (PKCS #5 v2.0)
    then
      error_msg( 'decrypt pkcs#5v2: unsupported key derivation OID: ' || l_oid );
      raise value_error;
    end if;
    check_tag( p_content, l_ind, c_SEQUENCE, 'decrypt pkcs#5v2: key derivation does not start with sequence' );
    l_len := get_len( p_content, l_ind );
    l_max_seq := l_ind + l_len;
    l_salt := get_octect( p_content, l_ind, 'No key derivation Salt' );
    l_iteration_count := to_number( get_integer( p_content, l_ind, 'No key derivation iterationCount' ), 'xxxxxxxx' );
    if l_ind < l_max_seq and utl_raw.substr( p_content, l_ind, 1 ) = c_INTEGER
    then
      l_keylength := to_number( get_integer( p_content, l_ind ), 'xxxxxxxx' );
    end if;
    l_oid := null;
    l_hash_type := HMAC_SH1;  -- default
    if l_ind < l_max_seq and utl_raw.substr( p_content, l_ind, 1 ) = c_OID
    then
      l_oid := get_oid( p_content, l_ind );
    elsif l_ind < l_max_seq and utl_raw.substr( p_content, l_ind, 1 ) = c_SEQUENCE
    then
      l_len := get_len( p_content, l_ind );
      l_oid := get_oid( p_content, l_ind, 'No pkcs#5 key derivation HMAC' );
    end if;
    if l_oid = '2A864886F70D0209' -- 1.2.840.113549.2.9 hmacWithSHA256 (RSADSI digestAlgorithm)
    then
      l_hash_type := HMAC_SH256;
    elsif l_oid = '2A864886F70D020B' -- 1.2.840.113549.2.11 hmacWithSHA512 (RSADSI digestAlgorithm)
    then
      l_hash_type := HMAC_SH512;
    elsif l_oid = '2A864886F70D020A' -- 1.2.840.113549.2.10 hmacWithSHA384 (RSADSI digestAlgorithm)
    then
      l_hash_type := HMAC_SH384;
    elsif l_oid = '2A864886F70D0208' -- 1.2.840.113549.2.8 hmacWithSHA224 (RSADSI digestAlgorithm)
    then
      l_hash_type := -1;
    elsif l_oid is not null
    then
      error_msg( 'decrypt pkcs#5v2: unsupported hmac OID: ' || l_oid );
      raise value_error;
    end if;
    l_ind := l_max_seq;
    check_and_skip_tag( p_content, l_ind, c_SEQUENCE, 'decrypt pkcs#5v2: encryptionScheme does not start with sequence' );
    l_oid := get_oid( p_content, l_ind, 'decrypt pkcs#5v2: no encryptionScheme OID' );
    l_iv := get_octect( p_content, l_ind, 'decrypt pkcs#5v2: no IV' );
    if l_oid = '608648016503040102' -- 2.16.840.1.101.3.4.1.2 aes128-CBC (NIST Algorithm)
    then
      debug_msg( 'pkcs#5 aes128-CBC' );
      l_algo := dbms_crypto.ENCRYPT_AES128 + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_PKCS5;
      l_keylength := coalesce( l_keylength, 16 );
    elsif l_oid = '60864801650304012A' -- 2.16.840.1.101.3.4.1.42 aes256-CBC (NIST Algorithm)
    then
      debug_msg( 'pkcs#5 aes256-CBC' );
      l_algo := dbms_crypto.ENCRYPT_AES256 + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_PKCS5;
      l_keylength := coalesce( l_keylength, 32 );
    end if;
    if l_algo is null
    then
      error_msg( 'decrypt pkcs#5v2: no supported encryptionScheme' );
      raise value_error;
    end if;
    for i in 1 .. 5
    loop
      l_tmp := utl_raw.concat( l_salt, to_char( i, 'fm0xxxxxxx' ) );
      for c in 1 .. l_iteration_count
      loop
        l_tmp := dbms_crypto.mac( l_tmp, l_hash_type, p_pw );
        if c = 1
        then
          l_tt := l_tmp;
        else
          l_tt := utl_raw.bit_xor( l_tt, l_tmp );
        end if;
      end loop;
      l_dk := utl_raw.concat( l_dk, l_tt );
      exit when utl_raw.length( l_dk ) >= l_keylength;
    end loop;
    l_dk := utl_raw.substr( l_dk, 1, l_keylength );
    return dbms_crypto.decrypt( get_bytes( utl_raw.substr( p_content, l_ind, 1 ), p_content, l_ind, 'decrypt pkcs#5v2: no encrypted content' )
                              , l_algo
                              , l_dk
                              , l_iv
                              );
  end;
  --
  procedure parse_pkcs12( p_key raw, p_pw raw, p_pk_parameters out tp_pk_parameters )
  is
    l_len pls_integer;
    l_ind pls_integer;
    l_ind2 pls_integer;
    l_ind_macData pls_integer;
    l_mac raw(3999);
    l_macSalt raw(3999);
    l_macIterations raw(3999);
    l_digest raw(3999);
    l_data raw(32767);
    l_ContentInfo raw(32767);
    l_oid raw(3999);
    --
    function derive_key
      ( p_pw raw
      , p_salt raw
      , p_id pls_integer
      , p_iterations pls_integer
      , p_n pls_integer
      )
    return raw
    is
      u pls_integer := 20;
      v pls_integer := 64;
      s raw(1000);
      p raw(1000);
      i raw(1000);
      d raw(1000);
      b raw(1000);
      iNew raw(1000);
      chunk raw(1000);
      x integer;
      result raw(1000);
      buf raw(1000);
      t_pw raw(1000);
      t_len1 pls_integer;
      t_len2 pls_integer;
    begin
      t_pw := utl_raw.concat( p_pw, '0000' );
      d := utl_raw.copies( to_char( p_id, 'fm0X' ), v );
      t_len1 := utl_raw.length( p_salt );
      t_len2 := v * ceil( t_len1 / v );
      s := utl_raw.copies( p_salt, ceil( t_len2 / t_len1 ) );
      s := utl_raw.substr( s, 1, t_len2 );
      t_len1 := utl_raw.length( t_pw );
      t_len2 := v * ceil( t_len1 / v );
      p := utl_raw.copies( t_pw, ceil( t_len2 / t_len1 ) );
      p := utl_raw.substr( p, 1, t_len2 );
      i := utl_raw.concat( s, p );
      for ci in 1 .. ceil( p_n / u )
      loop
        exit when utl_raw.length( result ) >= p_n;
        buf := utl_raw.concat( d, i );
        for j in 1 .. p_iterations
        loop
          buf := dbms_crypto.hash( buf, dbms_crypto.hash_sh1 );
        end loop;
        b := utl_raw.substr( utl_raw.copies( buf, ceil( v / u ) ), 1, v );
        iNew := null;
        for k in 0 .. utl_raw.length( i ) / v - 1
        loop
          x := 256;
          chunk := utl_raw.substr( i, k*v + 1, v );
          for l in reverse 1 .. v
          loop
            x := trunc( x / 256 );
            x := x + to_number( utl_raw.substr( b, l, 1 ), 'XX' ) + to_number( utl_raw.substr( chunk, l, 1 ), 'XX' );
            chunk := utl_raw.overlay( substr( to_char( x, 'FM0XXX' ), -2 ), chunk, l );
          end loop;
          iNew := utl_raw.concat( iNew, chunk );
        end loop;
        i := iNew;
        result := utl_raw.concat( result, buf );
      end loop;
      return utl_raw.substr( result, 1, p_n );
    end;
    --
    procedure parse_content( p_content raw )
    is
      l_ind pls_integer;
      l_ind2 pls_integer;
      l_ind3 pls_integer;
      l_ind4 pls_integer;
      l_oid raw(3999);
      l_content_len pls_integer;
      l_bag raw(32767);
      type tp_mkstore_item is record
        ( host varchar2(3999)
        , user varchar2(3999)
        , password varchar2(3999)
        );
      type tp_mkstore is table of tp_mkstore_item index by pls_integer;
      l_mkstore tp_mkstore;
      type tp_orapki_item is record
        ( private_key tp_pk_parameters
        , friendly_name varchar2(3999)
        );
      type tp_orapki is table of tp_orapki_item index by pls_integer;
      l_orapki tp_orapki;
      type tp_csr_item is record
        ( cn varchar2(3999)
        , friendly_name varchar2(3999)
        );
      type tp_csr is table of tp_csr_item index by pls_integer;
      l_csr tp_csr;
      l_entity varchar2(3999);
      l_value varchar2(3999);
      l_idx pls_integer;
      l_tag raw(1);
      --
      function get_friendly_name( p_attr raw )
      return varchar2
      is
        l_ind pls_integer;
        l_ind2 pls_integer;
        l_len pls_integer;
        l_len_attr pls_integer;
        l_rv varchar2(3999);
        l_tag raw(1);
        l_value raw(3999);
      begin
        if p_attr is not null
        then
          l_len_attr := utl_raw.length( p_attr );
          l_ind := 1;
          check_and_skip_tag( p_attr, l_ind, '31', 'Expected an SET of attributes.' );
          loop
            exit when l_ind > l_len_attr;
            check_tag( p_attr, l_ind, c_SEQUENCE, 'Expected an attributes SEQUENCE.' );
            l_len := get_len( p_attr, l_ind );
            l_ind2 := l_ind + l_len;
            l_oid := get_oid( p_attr, l_ind, 'Expected an attributes OID.' );
            check_and_skip_tag( p_attr, l_ind, '31', 'Expected an attributes SET.' );
            l_tag := utl_raw.substr( p_attr, l_ind, 1 );
            l_value := get_bytes( l_tag, p_attr, l_ind, 'Expected an attributes value.' );
            if l_oid = '2A864886F70D010914' -- friendlyName (for PKCS #12)
            then
              case
                when l_tag = '1E'
                then -- BMPString
                  l_rv := utl_i18n.raw_to_char( l_value, 'AL16UTF16' );
                when l_tag = '0C'
                then -- UTF8String
                  l_rv := utl_i18n.raw_to_char( l_value, 'AL32UT8' );
                when l_tag in ( '16' -- IA5String
                              , '13' -- PrintableString
                              )
                then
                  l_rv := utl_i18n.raw_to_char( l_value, 'US7ASCII' );
                else
                  debug_msg( 'Unhandled friendlyName string type ' || l_tag );
              end case;
              exit;
            end if;
            l_ind := l_ind2;
          end loop;
        end if;
        return l_rv;
      end;
    begin
      l_content_len := utl_raw.length( p_content );
      check_starting_sequence( p_content, l_ind );
      loop
        exit when l_ind > l_content_len;
        l_bag := get_bytes( c_SEQUENCE, p_content, l_ind, 'no bag' );
        l_ind2 := 1;
        l_oid := get_oid( l_bag, l_ind2 );
        check_tag( l_bag, l_ind2, 'A0', 'Expected Bag elem' );
        l_ind3 := get_len( l_bag, l_ind2 );
        l_ind3 := l_ind3 + l_ind2;
        if l_oid = '2A864886F70D010C0A0105' --  1.2.840.113549.1.12.10.1.5 pkcs-12-secretBag (PKCS #12 BagIds)
        then
          check_and_skip_tag( l_bag, l_ind2, c_SEQUENCE, 'Expected Bag sequence' );
          l_oid := get_oid( l_bag, l_ind2 );
          if l_oid = '2A864886F70D01100C0C' -- 1.2.840.113549.1.16.12.12 oracle.security.client ...
          then
            check_and_skip_tag( l_bag, l_ind2, 'A0', 'Expected oracle.security.client elem' );
            check_and_skip_tag( l_bag, l_ind2, c_SEQUENCE, 'Expected oracle.security.client sequence' );
            l_entity := utl_i18n.raw_to_char( get_bytes( '0C', l_bag, l_ind2, 'no UTF8 entity' ), 'AL32UTF8' );
            l_value := utl_i18n.raw_to_char( get_bytes( '0C', l_bag, l_ind2, 'no UTF8 value' ), 'AL32UTF8' );
            if l_entity like 'oracle.security.client.connect_string%'
            then -- mkstore createCredential
              l_idx := substr( l_entity, 38 );
              l_mkstore( l_idx ).host := l_value;
              debug_msg( 'mkstore entry: ' || l_value );
            elsif l_entity like 'oracle.security.client.password%'
            then -- mkstore createCredential
              l_idx := substr( l_entity, 32 );
              l_mkstore( l_idx ).password := l_value;
            elsif l_entity like 'oracle.security.client.username%'
            then -- mkstore createCredential
              l_idx := substr( l_entity, 32 );
              l_mkstore( l_idx ).user := l_value;
            else -- mkstore createEntry
              l_idx := l_mkstore.count + 1;
              l_mkstore( l_idx ).host := l_entity;
              l_mkstore( l_idx ).password := l_value;
              debug_msg( 'mkstore entry: ' || l_entity );
            end if;
          elsif l_oid = '1648810681770D010A' -- 0.22.72.134.247.13.1.10 orapki certificate request
          then
            l_idx := l_csr.count + 1;
            check_and_skip_tag( l_bag, l_ind2, 'A0', 'Expected orapki certificate request elem' );
            check_and_skip_tag( l_bag, l_ind2, c_OCTECT, 'Expected orapki certificate request OCTECT STRING' );
            check_and_skip_tag( l_bag, l_ind2, c_SEQUENCE, 'Expected orapki certificate request SEQUENCE 1' );
            check_and_skip_tag( l_bag, l_ind2, c_SEQUENCE, 'Expected orapki certificate request SEQUENCE 2' );
            l_value := get_integer( l_bag, l_ind2, 'Expected orapki certificate request version INTEGER' );
            check_tag( l_bag, l_ind2, c_SEQUENCE, 'Expected orapki certificate request SEQUENCE 3' );
            l_ind4 := get_len( l_bag, l_ind2 );
            l_ind4 := l_ind4 + l_ind2;
            loop
              exit when l_ind2 >= l_ind4;
              check_and_skip_tag( l_bag, l_ind2, '31', 'Expected orapki certificate request version SET' );
              check_and_skip_tag( l_bag, l_ind2, c_SEQUENCE, 'Expected orapki certificate request SEQUENCE 4' );
              l_oid := get_oid( l_bag, l_ind2, 'Expected orapki certificate request DN OID' );
              l_tag := utl_raw.substr( l_bag, l_ind2, 1 );
              l_value := get_bytes( l_tag, l_bag, l_ind2 );
              if l_oid = '550403' -- 2.5.4.3 commonName (X.520 DN component)
              then
                case
                  when l_tag = '1E'
                  then -- BMPString
                    l_csr( l_idx ).cn := utl_i18n.raw_to_char( l_value, 'AL16UTF16' );
                  when l_tag = '0C'
                  then -- UTF8String
                    l_csr( l_idx ).cn := utl_i18n.raw_to_char( l_value, 'AL32UT8' );
                  when l_tag in ( '16' -- IA5String
                                , '13' -- PrintableString
                                )
                  then
                    l_csr( l_idx ).cn := utl_i18n.raw_to_char( l_value, 'US7ASCII' );
                  else
                    debug_msg( 'Unhandled commonName string type ' || l_tag );
                end case;
                exit;
              end if;
            end loop;
            l_csr( l_idx ).friendly_name := get_friendly_name( utl_raw.substr( l_bag, l_ind3 ) );
            debug_msg( 'certificate request: ' || l_csr( l_idx ).friendly_name || ' ' || l_csr( l_idx ).cn );
          end if;
        elsif l_oid = '2A864886F70D010C0A0101' -- 1.2.840.113549.1.12.10.1.1 pkcs-12-keyBag (PKCS #12 BagIds)
        then
          l_idx := l_orapki.count + 1;
          if parse_der_pkcs8( utl_raw.substr( l_bag, l_ind2 ), l_orapki( l_idx ).private_key )
          then
            l_orapki( l_idx ).friendly_name := get_friendly_name( utl_raw.substr( l_bag, l_ind3 ) );
            debug_msg( 'keybag loaded: ' || l_orapki( l_idx ).friendly_name || ' ' || utl_raw.cast_to_varchar2( l_orapki( l_idx ).private_key(0) ) );
          else
            l_orapki.delete( l_idx );
            debug_msg( 'keybag not loaded' );
            debug_msg( utl_raw.substr( l_bag, l_ind2 ) );
          end if;
        elsif l_oid = '2A864886F70D010C0A0103' -- 1.2.840.113549.1.12.10.1.3 pkcs-12-certBag (PKCS #12 BagIds)
        then
          debug_msg( 'cert bag' );
        else
          debug_msg( 'bag OID ' || l_oid );
        end if;
      end loop;
      --
      for i in 1 .. l_mkstore.count
      loop
        if l_mkstore( i ).host = g_con.remote_host
        then
          p_pk_parameters(0) := utl_raw.cast_to_raw( 'password' );
          p_pk_parameters(1) := utl_raw.cast_to_raw( l_mkstore( i ).password );
          p_pk_parameters(2) := utl_raw.cast_to_raw( l_mkstore( i ).user );
          exit;
        end if;
      end loop;
      --
      if p_pk_parameters.count = 0 and l_orapki.count > 0
      then
        if l_orapki.count = 1
        then
          p_pk_parameters := l_orapki( 1 ).private_key;
        else
          <<csr_loop>>
          for i in 1 .. l_csr.count
          loop
            if l_csr( i ).cn = g_con.remote_host
            then
              for j in 1 .. l_orapki.count
              loop
                if l_orapki( j ).friendly_name = l_csr( i ).friendly_name
                then
                  p_pk_parameters := l_orapki( j ).private_key;
                  exit csr_loop;
                end if;
              end loop;
            end if;
          end loop;
        end if;
      end if;
    end;
    --
    function decrypt_rc2_cbc( p_encr raw, p_key raw, p_iv raw )
    return raw
    is
      l_iv raw(48);
      l_block raw(128);
      l_rv raw(32767);
      type tp_rc2 is table of pls_integer index by pls_integer;
      l_rc2key tp_rc2;
      --
      function shr(     x pls_integer, b pls_integer )
      return pls_integer
      is
      begin
        return trunc( x / case b
                        when 0  then 1
                        when 1  then 2
                        when 2  then 4
                        when 3  then 8
                        when 4  then 16
                        when 5  then 32
                        when 6  then 64
                        when 7  then 128
                        when 8  then 256
                        when 9  then 512
                        when 10 then 1024
                        when 11 then 2048
                        when 12 then 4096
                        when 13 then 8192
                        when 14 then 16384
                        when 15 then 32768
                        when 16 then 65536
                        when 24 then 16777216
                        when 28 then 268435456
                      end );
      end;
      --
      function ror16( x integer, b pls_integer )
      return integer
      is
        t integer := bitand( x, 65535 );
        --
        function bitor( x pls_integer, y pls_integer )
        return pls_integer
        is
        begin
          return bitand( x + y - bitand( x, y   ), 65535 );
        end;
        --
      begin
        return bitor( shr( t, b )
                    , bitand( t * case 16 -b
                                                    when 11 then 2048
                                                    when 13 then 8192
                                                    when 14 then 16384
                                                    when 15 then 32768
                                            end
                                      , 65535
                                      )
                          );
      end;
      --
      procedure init_key( p_key varchar2 )
      is
        l_pi_str varchar2(512);
        l_pi_int tp_rc2;
        l_len pls_integer;
        l_ksb pls_integer;
        l_tmp tp_rc2;
        --
        function bitxor( x pls_integer, y       pls_integer     )
        return pls_integer
        is
        begin
          return bitand( x + y - 2 * bitand( x, y ), 65535 );
        end;
        --
      begin
        l_pi_str := 'd978f9c419ddb5ed28e9fd794aa0d89dc67e37832b76538e624c6488448bfba2'
                     || '179a59f587b34f1361456d8d09817d32bd8f40eb86b77b0bf09521225c6b4e82'
                     || '54d66593ce60b21c7356c014a78cf1dc1275ca1f3bbee4d1423dd430a33cb626'
                     || '6fbf0eda4669075727f21d9bbc944303f811c7f690ef3ee706c3d52fc8661ed7'
                     || '08e8eade8052eef784aa72ac354d6a2a961ad2715a1549744b9fd05e0418a4ec'
                     || 'c2e0416e0f51cbcc2491af50a1f47039997c3a8523b8b47afc02365b25559731'
                     || '2d5dfa98e38a92ae05df2910676cbac9d300e6cfe19ea82c6316013f58e289a9'
                     || '0d38341bab33ffb0bb480c5fb9b1cd2ec5f3db47e5a59c770aa62068fe7fc1ad';
        for     i in 0 .. 511
        loop
          l_pi_int( i ) := to_number( substr( l_pi_str, i       * 2 + 1, 2 ), 'xx' );
        end     loop;
        l_len := length( p_key ) / 2;
        for     i in 0 .. l_len - 1
        loop
          l_tmp( i ) := to_number( substr( p_key, i     * 2 + 1, 2 ), 'xx' );
        end     loop;
        for     i in l_len .. 127
        loop
          l_tmp( i ) := l_pi_int( bitand( l_tmp( i - 1  ) + l_tmp( i - l_len ), 255 ) );
        end     loop;
        l_ksb := trunc( ( l_len * 8     + 7 ) / 8 );
        l_tmp( 128 - l_ksb ) := bitand( l_pi_int( l_tmp(        128 - l_ksb ) ), shr( 255, l_ksb * 8 - l_len * 8 ) );
        for     i in reverse 0 .. 127 - l_ksb
        loop
          l_tmp( i ) := bitand( l_pi_int( bitxor( l_tmp( i + 1  ), l_tmp( i + l_ksb ) ) ), 255 );
        end     loop;
        for     i in 0 .. 63
        loop
          l_rc2key(     i ) := l_tmp( 2 * i ) + l_tmp( 2 * i + 1 ) * 256;
        end     loop;
      end;
      --
      function rc2decrypt( p_block varchar2 )
      return raw
      is
        t_data0 pls_integer := to_number( substr( p_block, 13 ), 'XXXX' );
        t_data1 pls_integer := to_number( substr( p_block, 9, 4 ), 'XXXX' );
        t_data2 pls_integer := to_number( substr( p_block, 5, 4 ), 'XXXX' );
        t_data3 pls_integer := to_number( substr( p_block, 1, 4 ), 'XXXX' );
        j pls_integer := 63;
        --
        procedure steps( p1     in out pls_integer, p2 pls_integer, p3 pls_integer, p4 pls_integer, p5 pls_integer )
        is
        begin
          p1 := ror16( p1, p2 );
          p1 := p1 - l_rc2key( j ) - bitand( p3, p4     ) - bitand( - p3 - 1, p5 );
          j     := j - 1;
        end;
        --
        procedure demix( c pls_integer )
        is
        begin
          for i in 1 .. c
          loop
              steps( t_data3,   5, t_data2, t_data1, t_data0 );
                steps( t_data2, 3, t_data1, t_data0, t_data3 );
                steps( t_data1, 2, t_data0, t_data3, t_data2 );
                steps( t_data0, 1, t_data3, t_data2, t_data1 );
          end loop;
        end;
        --
        procedure demash
        is
        begin
          t_data3 := bitand( t_data3 - l_rc2key( bitand( t_data2, 63 ) ), 65535 );
          t_data2 := bitand( t_data2 - l_rc2key( bitand( t_data1, 63 ) ), 65535 );
          t_data1 := bitand( t_data1 - l_rc2key( bitand( t_data0, 63 ) ), 65535 );
          t_data0 := bitand( t_data0 - l_rc2key( bitand( t_data3, 63 ) ), 65535 );
        end;
      begin
        demix( 5 );
        demash;
        demix( 6 );
        demash;
        demix( 5 );
        return utl_raw.reverse( to_char( bitand( t_data3, 65535 ), 'fm0XXX' ) ||
                                to_char( bitand( t_data2, 65535 ), 'fm0XXX' ) ||
                                to_char( bitand( t_data1, 65535 ), 'fm0XXX' ) ||
                                to_char( bitand( t_data0, 65535 ), 'fm0XXX' ) );
      end;
    begin
      l_iv := p_iv;
      init_key( p_key );
      for i in 0 .. utl_raw.length( p_encr ) / 8 - 2
      loop
        l_block := utl_raw.substr( p_encr, i * 8 + 1, 8 );
        l_rv := utl_raw.concat( l_rv, utl_raw.bit_xor( rc2decrypt( utl_raw.reverse( l_block ) ), l_iv ) );
        l_iv := l_block;
      end loop;
      l_block := utl_raw.substr( p_encr, -8 );
      l_block := utl_raw.bit_xor( rc2decrypt( utl_raw.reverse( l_block ) ), l_iv );
      if utl_raw.substr( l_block, -1 ) != '08'
      then
        l_rv := utl_raw.concat( l_rv, utl_raw.substr( l_block, 1, 8 - to_number( utl_raw.substr( l_block, -1 ) ) ) );
      end if;
      return l_rv;
    end;
    --
    function decrypt_content( p_content raw, p_pw raw )
    return raw
    is
      l_ind pls_integer;
      l_oid raw(3999);
      l_salt raw(3999);
      l_iterations pls_integer;
      l_algo pls_integer;
      l_iv raw(100);
      l_key raw(100);
    begin
      l_ind := 1;
      if get_integer( p_content, l_ind, 'No version' ) != '00'
      then
        debug_msg( 'Only encrypted content version 0 supported' );
        raise value_error;
      end if;
      check_and_skip_tag( p_content, l_ind, c_SEQUENCE, 'no encryptedContentInfo' );
      if get_oid( p_content, l_ind, 'encryptedContentInfo PKCS#7 data expected' ) !=  '2A864886F70D010701' -- 1.2.840.113549.1.7.1 data (PKCS #7)
      then
        debug_msg( 'encryptedContentInfo Expected PKCS#7 data OID' );
        raise value_error;
      end if;
      check_and_skip_tag( p_content, l_ind, c_SEQUENCE, 'no PBE object' );
      l_oid := get_oid( p_content, l_ind, 'PBE oid' );
      if l_oid in ( '2A864886F70D010C0103' -- 1.2.840.113549.1.12.1.3 pbeWithSHAAnd3-KeyTripleDES-CBC (PKCS #12 PbeIds)
                  , '2A864886F70D010C0106' -- 1.2.840.113549.1.12.1.6 pbewithSHAAnd40BitRC2-CBC (PKCS #12 PbeIds)
                  , '2A864886F70D010C0101' -- 1.2.840.113549.1.12.1.1 pbeWithSHAAnd128BitRC4 (PKCS #12 PbeIds)
                  , '2A864886F70D010C0102' -- 1.2.840.113549.1.12.1.2 pbeWithSHAAnd40BitRC4 (PKCS #12 PbeIds)
                  , '2A864886F70D010C0104' -- 1.2.840.113549.1.12.1.4 pbeWithSHAAnd2-KeyTripleDES-CBC (PKCS #12 PbeIds)
                  , '2A864886F70D010C0105' -- 1.2.840.113549.1.12.1.5 pbeWithSHAAnd128BitRC2-CBC (PKCS #12 PbeIds)
                  )
      then
        check_and_skip_tag( p_content, l_ind, c_SEQUENCE, 'no PBE parameters' );
        l_salt := get_octect( p_content, l_ind, 'no PBE Salt' );
        l_iterations := to_number( get_integer( p_content, l_ind, 'no PBE Iterations' ), rpad( 'X', 8, 'X' ) );
        if l_oid = '2A864886F70D010C0103' -- pbeWithSHAAnd3-KeyTripleDES-CBC
        then
          l_key := derive_key( p_pw, l_salt, 1, l_iterations, 24 );
          l_iv := derive_key( p_pw, l_salt, 2, l_iterations, 8 );
          l_algo := dbms_crypto.DES3_CBC_PKCS5;
        elsif l_oid = '2A864886F70D010C0102' -- pbeWithSHAAnd40BitRC4
        then
          l_key := derive_key( p_pw, l_salt, 1, l_iterations, 5 );
          l_algo := dbms_crypto.ENCRYPT_RC4;
        elsif l_oid = '2A864886F70D010C0101' -- pbeWithSHAAnd128BitRC4
        then
          l_key := derive_key( p_pw, l_salt, 1, l_iterations, 16 );
          l_algo := dbms_crypto.ENCRYPT_RC4;
        elsif l_oid = '2A864886F70D010C0104' -- pbeWithSHAAnd2-KeyTripleDES-CBC
        then
          l_key := derive_key( p_pw, l_salt, 1, l_iterations, 24 );
          l_iv := derive_key( p_pw, l_salt, 2, l_iterations, 8 );
          l_algo := dbms_crypto.ENCRYPT_3DES_2KEY + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_PKCS5;
        elsif l_oid = '2A864886F70D010C0105' -- pbewithSHAAnd128BitRC2-CBC
        then
          l_key := derive_key( p_pw, l_salt, 1, l_iterations, 16 );
          l_iv := derive_key( p_pw, l_salt, 2, l_iterations, 8 );
          return decrypt_rc2_cbc( get_bytes( '80', p_content, l_ind, 'no decrypted content 2' ), l_key, l_iv );
        elsif l_oid = '2A864886F70D010C0106' -- pbewithSHAAnd40BitRC2-CBC
        then
          l_key := derive_key( p_pw, l_salt, 1, l_iterations, 5 );
          l_iv := derive_key( p_pw, l_salt, 2, l_iterations, 8 );
          return decrypt_rc2_cbc( get_bytes( '80', p_content, l_ind, 'no decrypted content 3' ), l_key, l_iv );
        end if;
      elsif l_oid = '2A864886F70D01050D' -- 1.2.840.113549.1.5.13 pkcs5PBES2 (PKCS #5 v2.0)
      then
        return decrypt_pkcs5( utl_raw.substr( p_content, l_ind ), utl_raw.convert( p_pw, 'AL32UTF8', 'AL16UTF16' ) );
      else
        debug_msg( 'unsupported PBE algorithm ' || l_oid );
        raise value_error;
      end if;
      return dbms_crypto.decrypt( get_bytes( '80', p_content, l_ind, 'no decrypted content' )
                                , l_algo
                                , l_key
                                , l_iv
                                );
    end;
  begin
    if p_key is null or p_pw is null
    then
      raise value_error;
    end if;
    check_starting_sequence( p_key, l_ind );
    if get_integer( p_key, l_ind, 'No version' ) != '03'
    then
      debug_msg( 'Only PKCS#12 version 3 supported' );
      raise value_error;
    end if;
    check_tag( p_key, l_ind, c_SEQUENCE, 'pkcs#12 no authSafe' );
    l_len := get_len( p_key, l_ind );
    l_ind_macData := l_ind + l_len;
    check_and_skip_tag( p_key, l_ind_macData, c_SEQUENCE, 'pkcs#12 no macData' );
    l_mac := get_bytes( c_SEQUENCE, p_key, l_ind_macData, 'pkcs#12 no mac' );
    l_macSalt := get_octect( p_key, l_ind_macData, 'pkcs#12 no macSalt' );
    if l_ind_macData <= utl_raw.length( p_key )
    then
      l_macIterations := get_integer( p_key, l_ind_macData, 'pkcs#12 no macIterations' );
    else
      l_macIterations := '01';
    end if;
    l_ind2 := 1;
    l_ind2 := l_ind2 + get_len( l_mac, l_ind2 );
    l_digest := get_octect( l_mac, l_ind2, 'pkcs#12 no digest' );
    l_ind2 := null;
    check_starting_sequence( l_mac, l_ind2 );
    if get_oid( l_mac, l_ind2, 'pkcs#12 no digestAlgorithm' ) !=  '2B0E03021A' -- 1.3.14.3.2.26 sha1 (OIW)
    then
      debug_msg( 'Only sha1 is supported as Digest Algorithm for PKCS#12 version 3' );
      raise value_error;
    end if;
    if get_oid( p_key, l_ind, 'pkcs#12 PKCS#7 data expected' ) !=  '2A864886F70D010701' -- 1.2.840.113549.1.7.1 data (PKCS #7)
    then
      debug_msg( 'Expected PKCS#7 data OID' );
      raise value_error;
    end if;
    check_and_skip_tag( p_key, l_ind, 'A0', 'Expected PKCS#7 data elem' );
    l_data := get_octect( p_key, l_ind, 'pkcs#12 no PKCS#7 AuthenticatedSafe' );
    if dbms_crypto.mac( l_data
                       , dbms_crypto.hmac_sh1
                       , derive_key( p_pw, l_macSalt, 3, to_number( l_macIterations, rpad( 'X', 16, 'X' ) ), 20 )
                       ) != l_digest
    then
      debug_msg( 'Wrong wallet password' );
      debug_msg( l_digest );
      debug_msg( dbms_crypto.mac( l_data
                                , dbms_crypto.hmac_sh1
                                , derive_key( p_pw, l_macSalt, 3, to_number( l_macIterations, rpad( 'X', 16, 'X' ) ), 20 )
                                ) );
      raise value_error;
    end if;
    l_ind := null;
    check_starting_sequence( l_data, l_ind );
    loop
      exit when l_ind > utl_raw.length( l_data );
      l_ContentInfo := get_bytes( c_SEQUENCE, l_data, l_ind, 'pkcs#12 no ContentInfo' );
      l_ind2 := 1;
      l_oid := get_oid( l_ContentInfo, l_ind2, 'PKCS#7 OID expected' );
      check_and_skip_tag( l_ContentInfo, l_ind2, 'A0', 'Expected PKCS#7 ContentInfo elem ' );
      if l_oid = '2A864886F70D010706' -- 1.2.840.113549.1.7.6 encryptedData (PKCS #7)
      then
        parse_content( decrypt_content( get_bytes( c_SEQUENCE, l_ContentInfo, l_ind2, 'pkcs#12 no EncryptedData' ), p_pw ) );
      elsif l_oid = '2A864886F70D010701' -- 1.2.840.113549.1.7.1 data (PKCS #7)
      then
        parse_content( get_octect( l_ContentInfo, l_ind2, 'pkcs#12 no Data' ) );
      else
        debug_msg( 'Unexpected PKCS#7 data OID ' || l_oid );
        raise value_error;
      end if;
    end loop;
  exception when value_error
    then
raise;
  end;
  --
  procedure login_wallet( i_wallet_path varchar2, i_user varchar2, i_wallet_password varchar2 := null, i_wallet_file varchar2 := null, i_log_level pls_integer := null )
  is
    l_prev_log_level pls_integer := g_log_level;
    l_wallet_file varchar2(3999);
    l_bfile bfile;
    l_wallet raw(32767);
    l_len pls_integer;
    l_ind pls_integer;
    l_pw raw(3999);
    l_host varchar2(1000);
    l_pk_parameters tp_pk_parameters;
  begin
    g_log_level := nvl( i_log_level, g_log_level );
    if i_wallet_file is null
    then
      if i_wallet_password is null
      then
        l_wallet_file := 'cwallet.sso';
      else
        l_wallet_file := 'ewallet.p12';
      end if;
    else
      l_wallet_file := i_wallet_file;
    end if;
    l_bfile := bfilename( i_wallet_path, l_wallet_file );
    dbms_lob.fileopen( l_bfile );
    l_wallet := dbms_lob.substr( l_bfile, 32767, 1 );
    dbms_lob.fileclose( l_bfile );
    if utl_raw.substr( l_wallet, 1, 3 ) = 'A1F84E' -- Oracle SSO
    then
      if utl_raw.substr( l_wallet, 4, 5 ) in ( '3600000006',  '3800000006' )
      then -- Oracle 11 and higher
        l_len := to_number( utl_raw.substr( l_wallet, 9, 4 ), 'XXXXXXXX' );
        if l_len = 65
        then -- Oracle 11
          l_pw := dbms_crypto.decrypt( utl_raw.cast_to_varchar2( utl_raw.substr( l_wallet, 30, 48 ) )
                                     , dbms_crypto.ENCRYPT_DES + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_PKCS5
                                     , utl_raw.cast_to_varchar2( utl_raw.substr( l_wallet, 14, 16 ) )
                                     );
        elsif l_len = 33
        then -- Oracle 12
          l_pw := dbms_crypto.decrypt( utl_raw.substr( l_wallet, 30, 16 )
                                     , dbms_crypto.ENCRYPT_AES + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_NONE
                                     , utl_raw.substr( l_wallet, 14, 16 )
                                     , 'c034d8311c02cef851f0144b81ed4bf2'
                                     );
        end if;
        if utl_raw.substr( l_wallet, 4, 1 ) = '38'
        then -- local wallet
          l_host := sys_context( 'userenv', 'server_host' );
          if instr( l_host, '.' ) > 0
          then
            l_host := substr( l_host, 1, instr( l_host, '.' ) - 1 );
          end if;
          l_host := upper( l_host || sys_context( 'userenv', 'os_user' ) );
          l_pw := dbms_crypto.mac( l_pw
                                 , dbms_crypto.hmac_sh1
                                 , utl_i18n.string_to_raw( l_host, 'AL32UTF8' )
                                 );
          l_pw := utl_raw.translate( utl_raw.substr( l_pw, 1, 16 )
                                   , utl_raw.xrange( '00', 'ff' )
                                   , utl_raw.concat( utl_raw.xrange( '01', '80' )
                                                   , utl_raw.xrange( '01', '80' )
                                                   )
                                   );
        end if;
      elsif utl_raw.substr( l_wallet, 4, 5 ) = '3600000005'
      then -- Oracle 10
        l_len := to_number( utl_raw.substr( l_wallet, 9, 4 ), 'XXXXXXXX' );
        l_pw := utl_raw.substr( l_wallet, 13, l_len );
      else
      raise_application_error( -20044, 'Unexpected SSO wallet format.' );
      end if;
      l_ind := 13 + l_len;
      l_pw := utl_raw.convert( l_pw, 'AL16UTF16', 'AL32UTF8' );
      parse_pkcs12( utl_raw.substr( l_wallet, l_ind ), l_pw, l_pk_parameters );
    else
      parse_pkcs12( l_wallet, utl_i18n.string_to_raw( i_wallet_password, 'AL16UTF16' ), l_pk_parameters );
    end if;
    if l_pk_parameters.count > 0
       and do_auth( i_user, l_pk_parameters )
    then
      info_msg( 'logged in' );
      if open_sftp
      then
        info_msg( 'sftp open' );
      else
        raise_application_error( -20031, 'Could not start sftp subsystem.' );
      end if;
    else
      raise_application_error( -20030, 'Could not login.' );
    end if;
    g_log_level := l_prev_log_level;
  exception
    when dbms_lob.NOEXIST_DIRECTORY then
      g_log_level := l_prev_log_level;
      debug_msg( 'Directory (object) for wallet does not exist: ' || i_wallet_path );
      raise_application_error( -20040, 'Directory (object) for wallet does not exist: ' || i_wallet_path );
    when dbms_lob.OPERATION_FAILED then
      g_log_level := l_prev_log_level;
      debug_msg( 'Can not read wallet file ' || l_wallet_file );
      raise_application_error( -20041, 'Can not read wallet file ' || l_wallet_file );
    when others then
      g_log_level := l_prev_log_level;
      error_msg( sqlerrm );
      raise;
  end;
  --
  procedure login_pk( i_user varchar2, i_path varchar2, i_file varchar2, i_password varchar2 := null, i_log_level pls_integer := null )
  is
    l_wallet_file varchar2(3999);
    l_bfile bfile;
    l_private_key raw(32767);
  begin
    l_bfile := bfilename( i_path, i_file );
    dbms_lob.fileopen( l_bfile );
    l_private_key := dbms_lob.substr( l_bfile, 32767, 1 );
    dbms_lob.fileclose( l_bfile );
    login( i_user => i_user, i_priv_key => l_private_key, i_passphrase => i_password, i_log_level => i_log_level );
  exception
    when dbms_lob.NOEXIST_DIRECTORY then
      raise_application_error( -20042, 'Directory (object) for private key does not exist: ' || i_path );
    when dbms_lob.OPERATION_FAILED then
      raise_application_error( -20043, 'Can not read private key ' || i_file );
  end;
end;
