---
title: "간단하게 배우는 react로 ant 사용하기(Dashboard) 5"
labels: ["TS","JS","react","frontend","antdesign"]
published: true
date: 2020-05-26T11:40:50+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 12
tistoryUrl: "https://yeolceo.tistory.com/12"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","frontend","antdesign"]
tistoryPostedAt: "2020-05-26 11:40:50"
language: ko
bloggerPostId: "3663844505875718520"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/ant.webp)

**간단하게 배우는 dashboard 마지막 글입니다.** 

**ant design의 기본기를 익히시기에 편한 글이었기를 바랍니다.** 

측면 메뉴바 측 사이더를 만들어주기 위해 components에서 Menu를 찾으시면 됩니다. 

가장 첫 번째 나오는 Menu컴포넌트의 코드를 보고 내용을 확인하시길 바랍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/2.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/1.webp)

간단히 요약한 코드입니다. 메뉴를 사용한다는 의미로 <Menu> 태그를 만들었고 그 안에 아이템으로 DashBoard를

설정했습니다. 큰 메뉴의 첫 번째에는 DashBoard 가 뜹니다. 그아래 SubMenu를 설정하는데 그 내부를 그룹화하는

ItemGroup이 있습니다. 메뉴를 그룹화하는데  타이틀 -> 즉 이름을 저런 이름의 그룹으로 만들어라 하는 내용입니다.

SubMenu안에 아이템을 넣어주면 아래와 같은 모양이 완성될 것입니다.

ant코드 위에 필요한 import나 const가 있다면 꼭 추가합시다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/3.webp)

하지만 보기 썩 좋지는 않습니다. 대시보드 아래 공간은 비어있고 그 옆으로 옵션이 삐져나옵니다.

  <Menu   defaultSelectedKeys={\['Dashboard'\]}   mode="inline"> 이 코드를 이용하여 인라인으로 변경해줍시다.

이제 키를 설정해줄 건데 위에도 보시면 defaultSelectedKeys 코드가 있습니다. 

키를 설정하는 이유는 키를 이용하여 메뉴에 이름을 지정하는 것입니다. 더욱 쉬운 조작을 위해 사용합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/1_1.webp)

icon과 키 설정을 추가하였습니다. 이만큼만 해도 벌써 대시보드 같은 느낌이 납니다. 

아마 그럴 겁니다.

하지만 중앙이 너무 허전합니다. 전체적인 틀을 만들었지만 원하는 내용을 넣으려면 화면의 구분이 필수입니다.

[https://ant.design/components/grid/](https://ant.design/components/grid/)

테이블의 가로세로 같은 개념입니다. grid 라는데 영어 뜻은 격자무늬라고 합니다. 저만 처음 안건 아닐 겁니다. 아마도

격자무늬를 만들어봅시다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/3_1.webp)

만약 웹을 어느 정도 해보셨다면 편하실 겁니다. Row와 Col을 이용하려 가로세로 설정을 해줍니다.

컨탠츠 안의 div를 이제 건드려봅시다.

  <div style={{background: '#fff', padding:24 , minHeight:800 }}>  제설 정입니다.

<Row gutter={\[16, 16\]}>  
                    <Col span={12}  style={{background: 'red' , height:'400px' }} />  
                    <Col span={12}  style={{background: 'black'}}  />  
 </Row> 

열을 먼저 만들고 그 안에 행을 설정합니다. 

가로 세로 설정까지 진행하는 이유는 신을 분할해놓고 사용하는 습관을 기르시길 바라기 때문입니다.

import React from 'react';

import { Button } from 'antd';

import './App.css';

import { Layout , Typography, Avatar , Menu ,Breadcrumb , Row, Col} from 'antd';

import { MailOutlined ,LaptopOutlined } from '@ant-design/icons';

import Iframe from 'react-iframe'

const { SubMenu } = Menu;

const { Title } = Typography;

const { Header, Footer, Sider, Content } = Layout;

function App() {

return (

<div className="App">

<Layout>

<Header style={{padding:15}}>

<Avatar style={{float:'right' }} src='./user-icon-test1.jpg' />

<Title style={{color:'white', float:'left'}} level={3}><LaptopOutlined />DashBoard-System</Title>

</Header>

<Layout>

<Sider style={{}}>

<Menu defaultSelectedKeys={\['Dashboard'\]} mode="inline">

<Menu.Item key='Dashboard'>

Dashboard

</Menu.Item>

<SubMenu key="sub1" icon={<MailOutlined />} title={<span>About US</span> }>

<Menu.ItemGroup key='AboutUS' title='Country 1'>

<Menu.Item key='location1' >Location 1</Menu.Item>

<Menu.Item key='location2' >Location 2</Menu.Item>

</Menu.ItemGroup>

</SubMenu>

</Menu>

</Sider>

<Layout>

<Content style={{ padding: '0 50px' }}>

<Breadcrumb style={{ margin: '16px 0' }}>

<Breadcrumb.Item>Dashboard</Breadcrumb.Item>

<Breadcrumb.Item>country1</Breadcrumb.Item>

</Breadcrumb>

<div style={{background: '#fff', padding:24 , minHeight:800 }}>

<Row gutter={\[16, 16\]}>

<Col span={12} style={{background: 'red' ,height:'400px' }} >

<Iframe url="[www.youtube.com/embed/fE2h3lGlOsk](http://www.youtube.com/embed/fE2h3lGlOsk)" width="770px" height="380px" id="myId" className="myClassname" display="initial" position="relative"/>

</Col>

<Col span={12} style={{background: 'black'}} />

</Row>

<Row gutter={\[16, 16\]}>

<Col span={12} style={{background: 'green' ,height:'400px' }}>

<Row gutter={\[16, 16\]}>

<Col span={12} style={{background: 'gray' ,height:'200px' }} />

<Col span={12} style={{background: 'black'}} />

</Row>

</Col>

<Col span={12} style={{background: 'pink'}} />

</Row>

</div>

</Content>

<Footer style={{ textAlign: 'center' }}>Ant Design ©2018 Created by Ant UED</Footer>

</Layout>

</Layout>

</Layout>

</div>

);

}

export default App;

아톰 에디터에서 그대로 복붙이 안돼서 옮겨 타서 붙여 넣었습니다. 

iframe부분은 삭제하셔도 무방합니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/1_2.webp)

최종 화면입니다. 씬 분할은 본인이 원하는 데로 설정하시면 다양한 대시보드를 만들 수 있다고 생각합니다. 

마지막 글까지 따라와 주셔서 감사하고 ant에 대한 전체적인 감이 잡히셨기를 바라는 바입니다. 있지는 예뻐서 넣은겁니

감사합니다.
