import json
from calendar import timegm
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Dict, Union

from zdppy_jwt.jose import jws

from .constants import ALGORITHMS
from .exceptions import ExpiredSignatureError, JWSError, JWTClaimsError, JWTError
from .utils import calculate_at_hash, timedelta_total_seconds


def encode(claims: Dict, key: str, algorithm: str = ALGORITHMS.HS256, headers: Dict = None,
           access_token: str = None) -> str:
    """
    对声明集进行编码并返回一个JWT字符串。
    JWTs是带有一些保留声明的JWS签名对象。
    claims：要加密的内容字典，包含token的主要内容
    key：用于加密的秘钥
    algorithm: 加密算法，默认是HS256
    headers: 请求头集合
    access_token: 如果存在，将被计算并添加到'claims'参数中
    示例: jwt.encode({'a': 'b'}, 'secret', algorithm='HS256')
    """
    # 转换日期格式
    for time_claim in ["exp", "iat", "nbf"]:
        if isinstance(claims.get(time_claim), datetime):
            claims[time_claim] = timegm(claims[time_claim].utctimetuple())

    # 计算token
    if access_token:
        claims["at_hash"] = calculate_at_hash(access_token, ALGORITHMS.HASHES[algorithm])

    # 生成jwt token
    return jws.sign(claims, key, headers=headers, algorithm=algorithm)


def decode(token: str, key: str, algorithms: Union[str, list] = None, options=None, audience=None, issuer=None,
           subject=None,
           access_token=None) -> Dict:
    """
    验证JWT字符串的签名并验证保留的声明。
    token: JWT生成的token
    key: 加密的秘钥
    algorithms: 签名算法

    示例:
    payload = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
    jwt.decode(payload, 'secret', algorithms='HS256')
    """

    defaults = {
        "verify_signature": True,
        "verify_aud": True,
        "verify_iat": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iss": True,
        "verify_sub": True,
        "verify_jti": True,
        "verify_at_hash": True,
        "require_aud": False,
        "require_iat": False,
        "require_exp": False,
        "require_nbf": False,
        "require_iss": False,
        "require_sub": False,
        "require_jti": False,
        "require_at_hash": False,
        "leeway": 0,
    }

    if options:
        defaults.update(options)

    verify_signature = defaults.get("verify_signature", True)

    try:
        payload = jws.verify(token, key, algorithms, verify=verify_signature)
    except JWSError as e:
        raise JWTError(e)

    # Needed for at_hash verification
    algorithm = jws.get_unverified_header(token)["alg"]

    try:
        claims = json.loads(payload.decode("utf-8"))
    except ValueError as e:
        raise JWTError("Invalid payload string: %s" % e)

    if not isinstance(claims, Mapping):
        raise JWTError("Invalid payload string: must be a json object")

    _validate_claims(
        claims,
        audience=audience,
        issuer=issuer,
        subject=subject,
        algorithm=algorithm,
        access_token=access_token,
        options=defaults,
    )

    # return claims
    return dict(claims)


def get_unverified_header(token):
    """Returns the decoded headers without verification of any kind.

    Args:
        token (str): A signed JWT to decode the headers from.

    Returns:
        dict: The dict representation of the token headers.

    Raises:
        JWTError: If there is an exception decoding the token.
    """
    try:
        headers = jws.get_unverified_headers(token)
    except Exception:
        raise JWTError("Error decoding token headers.")

    return headers


def get_unverified_headers(token):
    """Returns the decoded headers without verification of any kind.

    This is simply a wrapper of get_unverified_header() for backwards
    compatibility.

    Args:
        token (str): A signed JWT to decode the headers from.

    Returns:
        dict: The dict representation of the token headers.

    Raises:
        JWTError: If there is an exception decoding the token.
    """
    return get_unverified_header(token)


def get_unverified_claims(token):
    """Returns the decoded claims without verification of any kind.

    Args:
        token (str): A signed JWT to decode the headers from.

    Returns:
        dict: The dict representation of the token claims.

    Raises:
        JWTError: If there is an exception decoding the token.
    """
    try:
        claims = jws.get_unverified_claims(token)
    except Exception:
        raise JWTError("Error decoding token claims.")

    try:
        claims = json.loads(claims.decode("utf-8"))
    except ValueError as e:
        raise JWTError("Invalid claims string: %s" % e)

    if not isinstance(claims, Mapping):
        raise JWTError("Invalid claims string: must be a json object")

    return claims


def _validate_iat(claims):
    """Validates that the 'iat' claim is valid.

    The "iat" (issued at) claim identifies the time at which the JWT was
    issued.  This claim can be used to determine the age of the JWT.  Its
    value MUST be a number containing a NumericDate value.  Use of this
    claim is OPTIONAL.

    Args:
        claims (dict): The claims dictionary to validate.
    """

    if "iat" not in claims:
        return

    try:
        int(claims["iat"])
    except ValueError:
        raise JWTClaimsError("Issued At claim (iat) must be an integer.")


def _validate_nbf(claims, leeway=0):
    """Validates that the 'nbf' claim is valid.

    The "nbf" (not before) claim identifies the time before which the JWT
    MUST NOT be accepted for processing.  The processing of the "nbf"
    claim requires that the current date/time MUST be after or equal to
    the not-before date/time listed in the "nbf" claim.  Implementers MAY
    provide for some small leeway, usually no more than a few minutes, to
    account for clock skew.  Its value MUST be a number containing a
    NumericDate value.  Use of this claim is OPTIONAL.

    Args:
        claims (dict): The claims dictionary to validate.
        leeway (int): The number of seconds of skew that is allowed.
    """

    if "nbf" not in claims:
        return

    try:
        nbf = int(claims["nbf"])
    except ValueError:
        raise JWTClaimsError("Not Before claim (nbf) must be an integer.")

    now = timegm(datetime.utcnow().utctimetuple())

    if nbf > (now + leeway):
        raise JWTClaimsError("The token is not yet valid (nbf)")


def _validate_exp(claims, leeway=0):
    """Validates that the 'exp' claim is valid.

    The "exp" (expiration time) claim identifies the expiration time on
    or after which the JWT MUST NOT be accepted for processing.  The
    processing of the "exp" claim requires that the current date/time
    MUST be before the expiration date/time listed in the "exp" claim.
    Implementers MAY provide for some small leeway, usually no more than
    a few minutes, to account for clock skew.  Its value MUST be a number
    containing a NumericDate value.  Use of this claim is OPTIONAL.

    Args:
        claims (dict): The claims dictionary to validate.
        leeway (int): The number of seconds of skew that is allowed.
    """

    if "exp" not in claims:
        return

    try:
        exp = int(claims["exp"])
    except ValueError:
        raise JWTClaimsError("Expiration Time claim (exp) must be an integer.")

    now = timegm(datetime.utcnow().utctimetuple())

    if exp < (now - leeway):
        raise ExpiredSignatureError("Signature has expired.")


def _validate_aud(claims, audience=None):
    """Validates that the 'aud' claim is valid.

    The "aud" (audience) claim identifies the recipients that the JWT is
    intended for.  Each principal intended to process the JWT MUST
    identify itself with a value in the audience claim.  If the principal
    processing the claim does not identify itself with a value in the
    "aud" claim when this claim is present, then the JWT MUST be
    rejected.  In the general case, the "aud" value is an array of case-
    sensitive strings, each containing a StringOrURI value.  In the
    special case when the JWT has one audience, the "aud" value MAY be a
    single case-sensitive string containing a StringOrURI value.  The
    interpretation of audience values is generally application specific.
    Use of this claim is OPTIONAL.

    Args:
        claims (dict): The claims dictionary to validate.
        audience (str): The audience that is verifying the token.
    """

    if "aud" not in claims:
        # if audience:
        #     raise JWTError('Audience claim expected, but not in claims')
        return

    audience_claims = claims["aud"]
    if isinstance(audience_claims, str):
        audience_claims = [audience_claims]
    if not isinstance(audience_claims, list):
        raise JWTClaimsError("Invalid claim format in token")
    if any(not isinstance(c, str) for c in audience_claims):
        raise JWTClaimsError("Invalid claim format in token")
    if audience not in audience_claims:
        raise JWTClaimsError("Invalid audience")


def _validate_iss(claims, issuer=None):
    """Validates that the 'iss' claim is valid.

    The "iss" (issuer) claim identifies the principal that issued the
    JWT.  The processing of this claim is generally application specific.
    The "iss" value is a case-sensitive string containing a StringOrURI
    value.  Use of this claim is OPTIONAL.

    Args:
        claims (dict): The claims dictionary to validate.
        issuer (str or iterable): Acceptable value(s) for the issuer that
                                  signed the token.
    """

    if issuer is not None:
        if isinstance(issuer, str):
            issuer = (issuer,)
        if claims.get("iss") not in issuer:
            raise JWTClaimsError("Invalid issuer")


def _validate_sub(claims, subject=None):
    """Validates that the 'sub' claim is valid.

    The "sub" (subject) claim identifies the principal that is the
    subject of the JWT.  The claims in a JWT are normally statements
    about the subject.  The subject value MUST either be scoped to be
    locally unique in the context of the issuer or be globally unique.
    The processing of this claim is generally application specific.  The
    "sub" value is a case-sensitive string containing a StringOrURI
    value.  Use of this claim is OPTIONAL.

    Args:
        claims (dict): The claims dictionary to validate.
        subject (str): The subject of the token.
    """

    if "sub" not in claims:
        return

    if not isinstance(claims["sub"], str):
        raise JWTClaimsError("Subject must be a string.")

    if subject is not None:
        if claims.get("sub") != subject:
            raise JWTClaimsError("Invalid subject")


def _validate_jti(claims):
    """Validates that the 'jti' claim is valid.

    The "jti" (JWT ID) claim provides a unique identifier for the JWT.
    The identifier value MUST be assigned in a manner that ensures that
    there is a negligible probability that the same value will be
    accidentally assigned to a different data object; if the application
    uses multiple issuers, collisions MUST be prevented among values
    produced by different issuers as well.  The "jti" claim can be used
    to prevent the JWT from being replayed.  The "jti" value is a case-
    sensitive string.  Use of this claim is OPTIONAL.

    Args:
        claims (dict): The claims dictionary to validate.
    """
    if "jti" not in claims:
        return

    if not isinstance(claims["jti"], str):
        raise JWTClaimsError("JWT ID must be a string.")


def _validate_at_hash(claims, access_token, algorithm):
    """
    Validates that the 'at_hash' is valid.

    Its value is the base64url encoding of the left-most half of the hash
    of the octets of the ASCII representation of the access_token value,
    where the hash algorithm used is the hash algorithm used in the alg
    Header Parameter of the ID Token's JOSE Header. For instance, if the
    alg is RS256, hash the access_token value with SHA-256, then take the
    left-most 128 bits and base64url encode them. The at_hash value is a
    case sensitive string.  Use of this claim is OPTIONAL.

    Args:
      claims (dict): The claims dictionary to validate.
      access_token (str): The access token returned by the OpenID Provider.
      algorithm (str): The algorithm used to sign the JWT, as specified by
          the token headers.
    """
    if "at_hash" not in claims:
        return

    if not access_token:
        msg = "No access_token provided to compare against at_hash claim."
        raise JWTClaimsError(msg)

    try:
        expected_hash = calculate_at_hash(access_token, ALGORITHMS.HASHES[algorithm])
    except (TypeError, ValueError):
        msg = "Unable to calculate at_hash to verify against token claims."
        raise JWTClaimsError(msg)

    if claims["at_hash"] != expected_hash:
        raise JWTClaimsError("at_hash claim does not match access_token.")


def _validate_claims(claims, audience=None, issuer=None, subject=None, algorithm=None, access_token=None, options=None):
    leeway = options.get("leeway", 0)

    if isinstance(leeway, timedelta):
        leeway = timedelta_total_seconds(leeway)
    required_claims = [e[len("require_"):] for e in options.keys() if e.startswith("require_") and options[e]]
    for require_claim in required_claims:
        if require_claim not in claims:
            raise JWTError('missing required key "%s" among claims' % require_claim)
        else:
            options["verify_" + require_claim] = True  # override verify when required

    if not isinstance(audience, ((str,), type(None))):
        raise JWTError("audience must be a string or None")

    if options.get("verify_iat"):
        _validate_iat(claims)

    if options.get("verify_nbf"):
        _validate_nbf(claims, leeway=leeway)

    if options.get("verify_exp"):
        _validate_exp(claims, leeway=leeway)

    if options.get("verify_aud"):
        _validate_aud(claims, audience=audience)

    if options.get("verify_iss"):
        _validate_iss(claims, issuer=issuer)

    if options.get("verify_sub"):
        _validate_sub(claims, subject=subject)

    if options.get("verify_jti"):
        _validate_jti(claims)

    if options.get("verify_at_hash"):
        _validate_at_hash(claims, access_token, algorithm)
