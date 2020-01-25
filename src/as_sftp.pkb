create or replace package body as_sftp
is
  --
  type tp_mag is table of number index by pls_integer;
  --
  type tp_ec_point is record
    ( x tp_mag
    , y tp_mag
    );
  type tp_ec_curve is record
    ( prime tp_mag
    , a tp_mag
    , b tp_mag
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
  --
  -- big integers
  ccc number := 16; -- number of nibbles
  cm number := power( 16, ccc );
  cmm number := cm-1;
  cm2 number := cm / 2;
  cmi number := power( 16, -ccc );
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
  V_C raw(512) := utl_i18n.string_to_raw( 'SSH-2.0-as_sftp_0.02', 'US7ASCII' );
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
  SSH_FX_OK                constant number := 0;
  SSH_FX_EOF               constant number := 1;
  SSH_FX_NO_SUCH_FILE      constant number := 2;
  SSH_FX_PERMISSION_DENIED constant number := 3;
  SSH_FX_FAILURE           constant number := 4;
  SSH_FX_BAD_MESSAGE       constant number := 5;
  SSH_FX_NO_CONNECTION     constant number := 6;
  SSH_FX_CONNECTION_LOST   constant number := 7;
  SSH_FX_OP_UNSUPPORTED    constant number := 8;
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
    if g_log_level >= 3
    then
      log( p_msg );
    end if;
  end;
  --
  procedure log_msg( p_msg in varchar2 )
  is
  begin
    if g_log_level >= 2
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
    while rv( rv.last ) = 0
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
  function double_point( pa tp_ec_point, pc tp_ec_curve )
  return tp_ec_point
  is
    slope tp_mag;
    rv tp_ec_point;
  begin
    if pa.x.count = 0
    then
      return pa;
    end if;
    slope := nmul( powmod( pa.x, mag( '02' ), pc.prime ), 3 );
    slope := xmod( radd( slope, pc.a ), pc.prime );
    slope := mulmod( slope, powmod( nmul( pa.y, 2 ), nsub( pc.prime, 2 ), pc.prime ), pc.prime );
    rv.x := submod( powmod( slope, mag( '02' ), pc.prime ), xmod( nmul( pa.x, 2 ), pc.prime ), pc.prime );
    rv.y := mulmod( slope, submod( pa.x, rv.x, pc.prime ), pc.prime );
    rv.y := submod( rv.y, pa.y, pc.prime );
--    info_msg( 'dbl nx ' || demag( rv.x ) );
--    info_msg( 'dbl ny ' || demag( rv.y ) );
    return rv;
    exception when others then
      error_msg( dbms_utility.format_error_backtrace );
      error_msg( 'x ' || demag( pa.x ) );
      error_msg( 'y ' || demag( pa.y ) );
      raise;
  end;
  -- 
  function add_point( pa tp_ec_point, pb tp_ec_point, pc tp_ec_curve )
  return tp_ec_point
  is
    slope tp_mag;
    rv tp_ec_point;
  begin
    if requal( pa.x, pb.x ) and requal( pa.y, pb.y )
    then
      return double_point( pa, pc );
    elsif pa.x.count = 0
    then
      return pb;
    elsif pb.x.count = 0
    then
      return pa;
    end if;
    slope := powmod( submod( pa.x, pb.x, pc.prime ), nsub( pc.prime, 2 ), pc.prime );
    slope := mulmod( submod( pa.y, pb.y, pc.prime ), slope, pc.prime );
    rv.x := powmod( slope, mag( '02' ), pc.prime );
    rv.x := submod( submod( rv.x, pa.x, pc.prime ), pb.x, pc.prime );
    rv.y := mulmod( slope, submod( pb.x, rv.x, pc.prime ), pc.prime );
    rv.y := submod( rv.y, pb.y, pc.prime );
--    info_msg( 'add nx ' || demag( rv.x ) );
--    info_msg( 'add ny ' || demag( rv.y ) );
    return rv;
  end;
  -- 
  function multiply_point( pa tp_ec_point, pm tp_mag, pc tp_ec_curve )
  return tp_ec_point
  is
    nr number;
    hb boolean := false;
    sb varchar2(3999);
    rv tp_ec_point;
  begin
    sb := nvl( ltrim( demag( xmod( pm, pc.prime ) ), '0' ), '0' );
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
          rv := double_point( rv, pc );        
        end if;
        if bitand( nr, power( 2, j ) ) > 0
        then
          rv := add_point( rv, pa, pc );
        end if;
      end loop;
    end loop;
--    info_msg( 'nx ' || demag( rv.x ) );
--    info_msg( 'ny ' || demag( rv.y ) );
    return rv;
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
                                                  , rpad( '0', 32, 'X' )
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
      l_dss_r raw(20);
      l_dss_s raw(20);
      l_w raw(32767);
      l_u1 raw(32767);
      l_u2 raw(32767);
      l_v raw(32767);
      --
      l_rsa_e raw(32767);
      l_rsa_n raw(32767);
      l_rsa_s raw(32767);
      l_hash_len pls_integer;      
      l_hash_type pls_integer;
    begin
      l_idx := 1;
      get_string( l_idx, p_host_key, l_tmp );
      debug_msg( 'validating host key using algorithm ' || utl_raw.cast_to_varchar2( l_tmp ) );
      if l_tmp = hextoraw( '7373682D647373' ) -- ssh-dss
      then
        info_msg( 'trying ssh-dss' );
        get_mpint( l_idx, p_host_key, l_p );
        get_mpint( l_idx, p_host_key, l_q );
        get_mpint( l_idx, p_host_key, l_g );
        get_mpint( l_idx, p_host_key, l_y );
        l_idx := 1;
        get_string( l_idx, p_signature, l_tmp );
        if l_tmp != hextoraw( '7373682D647373' ) -- ssh-dss
        then
          raise_application_error( -20011, 'ssh-dss not OK' );
        end if;
        get_string( l_idx, p_signature, l_tmp );
        l_dss_r := utl_raw.substr( l_tmp, 1, 20 );
        l_dss_s := utl_raw.substr( l_tmp, 21, 20 );
        l_w := powmod( l_dss_s, demag( nsub( mag( l_q ), 2 ) ), l_q );
        l_u1 := demag( xmod( rmul( mag( dbms_crypto.hash( l_H, HASH_SH1 ) ), mag( l_w ) ), mag( l_q ) ) );
        l_u2 := demag( xmod( rmul( mag( l_dss_r ), mag( l_w ) ), mag( l_q ) ) );
        l_v := demag( xmod( xmod( rmul( mag( powmod( l_g, l_u1, l_p ) ), mag( powmod( l_y, l_u2, l_p ) ) ), mag( l_p ) ), mag( l_q ) ) );
        if l_v != l_dss_r
        then
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
          raise_application_error( -20015, 'ssh-rsa not OK' );
        end if;
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
    show_name_list( kex_algorithms );
    show_name_list( public_key_algorithms );
    --show_name_list( encr_algo_client_to_server );
    show_name_list( encr_algo_server_to_client );
    --show_name_list( mac_algo_client_to_server );
    show_name_list( mac_algo_server_to_client );
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
    show_name_list( my_public_key_algorithms );
    my_encr_algo_client_to_server := tp_name_list( 'aes128-cbc', '3des-cbc' );
    add2name_list( my_encr_algo_client_to_server, 'aes256-cbc' );
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
      raise_application_error( -20003, 'Could not find matching encryption algorithm server to client' );
    end if;
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
      raise_application_error( -20008, 'Could not find matching public key algorithm' );
    end if;
    --
    for i in my_kex_algorithms.first .. my_kex_algorithms.last
    loop
      if my_kex_algorithms(i) member of kex_algorithms
      then
        l_kex_algorithm := my_kex_algorithms(i);
        exit;
      end if;
    end loop;
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
        l_pa tp_ec_point;
        l_pb tp_ec_point;
        l_order tp_mag;
        l_xxx tp_mag;
        l_nlen pls_integer; -- in bytes
      begin
        l_buf := SSH_MSG_KEX_ECDH_INIT;
        if l_kex_algorithm = 'ecdh-sha2-nistp256'
        then
          l_nlen := 32;
          l_curve.prime := mag( 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF' );
          l_curve.a :=     mag( 'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc' );
          l_curve.b :=     mag( '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b' );
          l_pa.x := mag( '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296' );
          l_pa.y := mag( '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5' );
          l_order := mag( 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551' );
          l_xxx := mag( dbms_crypto.randombytes( 4 ) );
          l_hash_type := HASH_SH256;
        elsif l_kex_algorithm = 'ecdh-sha2-nistp384'
        then
          l_nlen := 48;
          l_curve.prime := mag( 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff' );
          l_curve.a :=     mag( 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc' );
          l_curve.b :=     mag( 'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef' );
          l_pa.x := mag( 'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7' );
          l_pa.y := mag( '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f' );
          l_order := mag( 'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973' );
          l_xxx := mag( dbms_crypto.randombytes( 4 ) );
          l_hash_type := HASH_SH384;
        elsif l_kex_algorithm = 'ecdh-sha2-nistp521'
        then
          l_nlen := 66;
          l_curve.prime := mag( '1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' );
          l_curve.a :=     mag( '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc' );
          l_curve.b :=     mag( '51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00' );
          l_pa.x := mag( 'c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66' );
          l_pa.y := mag( '11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650' );
          l_order := mag( '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409' );
          l_xxx := mag( dbms_crypto.randombytes( 4 ) );
          l_hash_type := HASH_SH512;
        end if;
        l_pb  := multiply_point( l_pa, l_xxx, l_curve );
        l_qc := utl_raw.concat( '04', lpad( demag( l_pb.x ), 2 * l_nlen, '0' ), lpad( demag( l_pb.y ), 2 * l_nlen, '0' ) );
        append_mpint( l_buf, l_qc );
        write_packet( l_buf );
        read_until( l_buf, SSH_MSG_KEX_ECDH_REPLY );
        l_idx := 2;
        get_string( l_idx, l_buf, K_S );
        get_string( l_idx, l_buf, l_qs );
        get_string( l_idx, l_buf, l_s );
        if utl_raw.length( l_qs ) = 1 + 2 * l_nlen
        then
          l_pa.x := mag( utl_raw.substr( l_qs, 2, l_nlen ) );
          l_pa.y := mag( utl_raw.substr( l_qs, 2 + l_nlen, l_nlen ) );
        else
          raise_application_error( -20016, 'Point compression not supported.' );
        end if;
        -- validate if l_qs is point on curve
        l_pb  := multiply_point( l_pa, l_xxx, l_curve );
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
    info_msg( 'using ' || l_kex_algorithm );
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
    g_iv_cypher_s2c_ctr := to_number( g_iv_cypher_s2c, rpad( '0', 32, 'X' ) );
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
  function do_auth( p_user varchar2, p_pw varchar2 )
  return boolean
  is
    l_rv boolean;
    l_pk_OK boolean;
    l_idx pls_integer;
    l_buf raw(32767);
    l_buf2 raw(32767);
    l_buf3 raw(32767);
    auth_methods tp_name_list;
    l_modulus  raw(2000);
    l_pub_exp  raw(2000);
    l_priv_exp raw(2000);
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
        auth_methods := read_name_list( l_idx, l_buf );
        show_name_list( auth_methods );
    end case;
    if l_rv
    then
      return true;
    end if;
    l_buf := SSH_MSG_USERAUTH_REQUEST;
    append_string( l_buf, utl_i18n.string_to_raw( p_user, 'AL32UTF8' ) );
    append_string( l_buf, utl_i18n.string_to_raw( 'ssh-connection', 'US7ASCII' ) );
    append_string( l_buf, utl_i18n.string_to_raw( 'password', 'US7ASCII' ) );
    append_boolean( l_buf, false );
    append_string( l_buf, utl_i18n.string_to_raw( p_pw, 'AL32UTF8' ) );
    write_packet( l_buf );
    read_until( l_buf, SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE );
    case utl_raw.substr( l_buf, 1, 1 )
      when SSH_MSG_USERAUTH_SUCCESS
      then
        l_rv := true;
        info_msg( 'connect with password' );
      when SSH_MSG_USERAUTH_FAILURE
      then
        l_idx := 2;
        auth_methods := read_name_list( l_idx, l_buf );
    end case;
    return l_rv;
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
          p_buf := utl_raw.substr( p_buf, 5 );
          while utl_raw.length( p_buf ) < l_len
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
--
    SSH_FILEXFER_ATTR_SIZE         number := 1;
    SSH_FILEXFER_ATTR_UIDGID       number := 2;
    SSH_FILEXFER_ATTR_PERMISSIONS  number := 4;
    SSH_FILEXFER_ATTR_ACMODTIME    number := 8;
    SSH_FILEXFER_ATTR_EXTENDED     number := 2147483648;
--
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
            l_dir_line.is_directory := utl_raw.substr( l_buf2, 1, 1 ) = '64'; -- d
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
  procedure login( i_user varchar2, i_password varchar2 )
  is
  begin
    if do_auth( i_user, i_password )
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
  end;
  --
  procedure open_connection( p_host varchar2, p_port pls_integer, p_fingerprint varchar2, p_trust boolean )
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
      init_hmac_ids;
      --
      read_until( l_buf, SSH_MSG_KEXINIT );
      handle_kex( l_buf, p_fingerprint, p_trust );
    end if;
  end;
  --
  procedure open_connection( i_host varchar2, i_port pls_integer := 22 )
  is
  begin
    open_connection( i_host, i_port, null, null );
  end;
  --
  procedure open_connection( i_host varchar2, i_trust_server boolean, i_port pls_integer := 22 )
  is
  begin
    open_connection( i_host, i_port, null, i_trust_server );
  end;
  --
  procedure open_connection( i_host varchar2, i_fingerprint varchar2, i_port pls_integer := 22 )
  is
  begin
    open_connection( i_host, i_port, i_fingerprint, null );
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
end;
