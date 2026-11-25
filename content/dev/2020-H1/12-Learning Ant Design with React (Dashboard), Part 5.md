---
title: "Learning Ant Design with React (Dashboard), Part 5"
labels: ["TS","JS","react","frontend","antdesign","Archive"]
published: true
date: 2020-05-26T11:40:50+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 12
tistoryUrl: "https://yeolceo.tistory.com/12"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","frontend","antdesign"]
tistoryPostedAt: "2020-05-26 11:40:50"
language: en
bloggerPostId: "3663844505875718520"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/ant.webp)

**This is the last post in the simple dashboard series.**

**I hope it's been an easy way to pick up the basics of Ant Design.**

To build the Sider, the side menu bar, look for Menu under Components.

Check out the code for the very first Menu component example.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/2.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/1.webp)

Here's a trimmed-down version of the code. I created a <Menu> tag to use the menu and added DashBoard as an item inside it.

DashBoard appears first in the top-level menu. Below it I set up a SubMenu, and inside that there's an ItemGroup

that groups its contents. It groups the menu items and says: make a group with this title, i.e. this name.

Put items inside the SubMenu and you'll get something like the screenshot below.

If the Ant code needs any imports or consts at the top, make sure to add them.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/3.webp)

But it doesn't look great. The space under Dashboard is empty, and the options stick out to the side.

  Use <Menu   defaultSelectedKeys={\['Dashboard'\]}   mode="inline"> to switch it to inline mode.

Next we'll set keys. As you can see above, there's already a defaultSelectedKeys prop.

Keys let you identify each menu item by name, which makes them much easier to work with.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/1_1.webp)

I added icons and keys. Even just this much already makes it feel like a dashboard.

Probably.

But the center is still too empty. We've built the overall frame, but to add the content you want, you need to divide up the screen.

[https://ant.design/components/grid/](https://ant.design/components/grid/)

It's the same idea as a table's rows and columns. It's called a grid, which literally means a lattice pattern. I'm probably not the only one who just learned that.

Let's build a grid.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/3_1.webp)

If you've done some web work, this will feel familiar. We use Row and Col to set up the horizontal and vertical layout.

Now let's work on the div inside Content.

  <div style={{background: '#fff', padding:24 , minHeight:800 }}>  These are my settings.

<Row gutter={\[16, 16\]}>  
                    <Col span={12}  style={{background: 'red' , height:'400px' }} />  
                    <Col span={12}  style={{background: 'black'}}  />  
 </Row> 

Create the row first, then set up the columns inside it.

The reason I go as far as setting up rows and columns is that I want you to build the habit of splitting your screen into sections before you fill them.

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

Copy-pasting straight from the Atom editor didn't work, so I moved it over and pasted it here.

Feel free to delete the iframe part.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/12/1_2.webp)

Here's the final screen. I think you can build all kinds of dashboards by splitting the sections however you like.

Thanks for following along to the last post, and I hope you've got an overall feel for Ant. (I put ITZY in there just because they're pretty.)

Thank you.
