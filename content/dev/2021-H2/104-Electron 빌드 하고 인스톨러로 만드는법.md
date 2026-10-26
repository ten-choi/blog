---
title: "Electron 빌드 하고 인스톨러로 만드는법"
labels: ["ETC","Electron","Installer","build","builder"]
published: false
date: 2021-08-02T16:35:45+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 104
tistoryUrl: "https://yeolceo.tistory.com/104"
tistoryCategory: "ETC/Electron"
tistoryTags: ["Installer","build","builder","Electron"]
tistoryPostedAt: "2021-08-02 16:35:45"
language: ko
bloggerPostId: "3446085168787141758"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/104/img.webp)

## Builder 만들기

node 14.17.1 버전을 사용합니다. 

먼저 본인이 빌드할 일렉트론 파일을 준비합니다.

아래의 라이브러리를 글로벌(-g)로 다운로드합니다. 일렉트론 빌더 라이브러리입니다.

```html
npm install -g electron-builder
```

json 파일을 살펴봅시다.

scripts에서 build 할 때 어떤 플랫폼으로 빌드할지 정해줍니다.

패키징 파일이 보여질 이미지 경로도 정해줍니다. 스크립트와 빌드 이외에는 json을 건드릴 필요가 없습니다.

```html
{
  "name": "프로젝트이름",

  "version": "1.0.0",

  "description": "본인 일렉트론 앱 설명",

  "main": "main.js",

  "scripts": {
    "build:osx": "electron-builder --mac",
    "build:linux": "npm run build:linux32 && npm run build:linux64",
    "build:linux32": "electron-builder --linux --ia32",
    "build:linux64": "electron-builder --linux --x64",
    "build:win": "npm run build:win32 && npm run build:win64",
    "build:win32": "electron-builder --win portable --ia32",
    "build:win64": "electron-builder --win portable --x64"
  },

  "build": {
    "win": {
      "icon": "패키징 파일 이미지 경로"
    }
  }
}
```

이제 npm run build:win64 명령어를 윈도 64에서 사용할 일렉트론 파일 빌드가 완료됩니다. 

## Installer 만들기

빌드 파일을 installer 형태로 바꿔봅시다.

[https://wixtoolset.org/releases/](https://wixtoolset.org/releases/)

이 경로에서 다운로드 링크를 누르고 아래 그림을 찾아줍니다. exe 파일을 다운로드한 후 실행해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/104/img_1.webp)

실행되면 인스톨해주세요. 경로에서 Program Files(x86) 밑에 WIX 관련 폴더가 생깁니다.

그 디렉터리의 bin 경로에 환경변수 설정해줍니다.

CMD에서 candle 입력했을 때 뭐라도 나오면 환경변수가 잘 설정된 겁니다

npm에서 WIX 인스톨러 라이브러리를 다운로드합니다.

 **npm install electron-wix-msi --save-dev** 

(파이썬 설치 및 환경변수 필요한 라이브러리입니다.)

electron-wix-msi는 문법이 ES6를 주로 사용했기 때문에 babel을 설치하여 실행오류를 막아줍니다. 

**npm install babel-cli --dev babel-preset-env --dev babel-preset-stage-3 --dev**

babel을 적용하기 위해 기본 경로에. babelrc라는 파일을 만들어줍니다. 아래와 같은 내용을 추가해줍니다.

```html
{
    "presets": ["env", "stage-3"]
}
```

인스톨러를 만들 파일을 만들어줍니다. builder.js 파일을 만들어줍니다.

```html
import { MSICreator } from 'electron-wix-msi';

//msi 파일 크리에이터 
const msiCreator = new MSICreator({
  appDirectory: '빌드하여 생성된(unpacked한) 일렉트론 디렉토리',
  description: '설명',
  exe: '빌드하여 생성된 일렉트론 디렉토리에서의 exe파일 이름',
  name: '이름',
  manufacturer: '내용',
  version: '1.1.0',
  outputDirectory: '인스톨러를 저장할 디렉토리',
  ui : {
    chooseDirectory : true
  },
  shortcutName : '바로가기이름'
});

//생성 및 컴파일
msiCreator.create().then(function(){
    msiCreator.compile();
})
```

일렉트론 파일을 msi 인스톨러로 만들어줄 빌더 파일입니다.

scripts에 인스톨러 하나를 만들어줍니다. babel-node builder.js 방금 만든 buillder.js파일이며 babel-node는 아까 세팅한 babel 적용하겠다는 의미입니다.

```html
"scripts": {
    "build_installer": "babel-node builder.js"
 }
```

npm run build\_installer 

msi 파일이 만들어집니다. 외부 가서 설치해야 하실 때 사용하시면 됩니다. 

env를 사용하시는 분은 빌드 후에 디렉터리에 env파일을 넣고 installer로 만드시면 됩니다.

참고한 블로그 입니다. [https://lts0606.tistory.com/475](https://lts0606.tistory.com/475)

성실한 코딩 하세요.
