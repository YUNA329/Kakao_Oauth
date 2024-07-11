import os

import requests
import jwt

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from rest_framework_simplejwt.tokens import RefreshToken

from auths.models import MutsaUser
from auths.serializers import KakaoLoginRequestSerializer, KakaoRegisterRequestSerializer, MutsaUserResponseSerializer

class KakaoAccessTokenException(Exception):
    pass

class KakaoOIDCException(Exception):
    pass

class KakaoDataException(Exception):
    pass

def exchange_kakao_access_token(access_code):
    response = requests.post(
        'https://kauth.kakao.com/oauth/token',
        headers={
            'Content-type': 'application/x-www-form-urlencoded;charset=utf-8',
        },
        data={
            'grant_type': 'authorization_code',
            'client_id': os.environ.get('KAKAO_REST_API_KEY'),
            'redirect_uri': os.environ.get('KAKAO_REDIRECT_URI'),
            'code': access_code,
        },
    )
    if response.status_code >= 300:
        raise KakaoAccessTokenException()
    return response.json()

def extract_kakao_nickname(kakao_data):
    id_token = kakao_data.get('id_token', None)
    if id_token is None:
        raise KakaoDataException()
    
    jwks_client = jwt.PyJWKClient(os.environ.get('KAKAO_OIDC_URI'))
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    signing_algol = jwt.get_unverified_header(id_token)['alg']
    try:
        payload = jwt.decode(
            id_token,
            key=signing_key.key,
            algorithms=[signing_algol],
            audience=os.environ.get('KAKAO_REST_API_KEY'),
        )
    except jwt.InvalidTokenError:
        raise KakaoOIDCException()
    return payload['nickname']

@api_view(['POST'])
@permission_classes([AllowAny])
def kakao_login(request):
    serializer = KakaoLoginRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data

    try:
        kakao_data = exchange_kakao_access_token(data['access_code'])
        nickname = extract_kakao_nickname(kakao_data)
    except KakaoAccessTokenException:
        return Response({'detail': 'Access token 교환에 실패했습니다.'}, status=401)
    except KakaoDataException:
        return Response({'detail': 'OIDC token 정보를 확인할 수 없습니다.'}, status=401)
    except KakaoOIDCException:
        return Response({'detail': 'OIDC 인증에 실패했습니다.'}, status=401)

    try:
        user = MutsaUser.objects.get(nickname=nickname)
    except MutsaUser.DoesNotExist:
        return Response({'detail': '존재하지 않는 사용자입니다.'}, status=404)

    refresh = RefreshToken.for_user(user)
    return Response({
        'access_token': str(refresh.access_token),
        'refresh_token': str(refresh)
    })

@api_view(['POST'])
@permission_classes([AllowAny])
def kakao_register(request):
    serializer = KakaoRegisterRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data

    try:
        kakao_data = exchange_kakao_access_token(data['access_code'])
        nickname = extract_kakao_nickname(kakao_data)
    except KakaoAccessTokenException:
        return Response({'detail': 'Access token 교환에 실패했습니다.'}, status=401)
    except KakaoDataException:
        return Response({'detail': 'OIDC token 정보를 확인할 수 없습니다.'}, status=401)
    except KakaoOIDCException:
        return Response({'detail': 'OIDC 인증에 실패했습니다.'}, status=401)

    ok = False
    try:
        user = MutsaUser.objects.get(nickname=nickname)
    except MutsaUser.DoesNotExist:
        ok = True

    if not ok:
        return Response({'detail': '이미 등록 된 사용자를 중복 등록할 수 없습니다.'}, status=400)

    user = MutsaUser.objects.create_user(nickname=nickname, description=data['description'])
    refresh = RefreshToken.for_user(user)
    return Response({
        'access_token': str(refresh.access_token),
        'refresh_token': str(refresh)
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify(request):
    return Response({'datail': 'Token is verified.'}, status=200)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_detail(request):
    serializer = MutsaUserResponseSerializer(request.user)
    return Response(serializer.data)
