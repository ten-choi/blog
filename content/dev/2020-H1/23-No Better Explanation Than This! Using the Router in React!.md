---
title: "No Better Explanation Than This! Using the Router in React!"
labels: ["TS","JS","react","Archive"]
published: true
date: 2020-06-12T16:14:00+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 23
tistoryUrl: "https://yeolceo.tistory.com/23"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","react"]
tistoryPostedAt: "2020-06-12 16:14:00"
language: en
bloggerPostId: "6909343833694761749"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/23/img.webp)

## **\-What Is the Router in React?**

**It's a technique for showing different screens in an SPA (single-page application) just by setting paths.**

Let's compare it with plain HTML files. In HTML, if you have three screens to show, you have three HTML files, each with its own path,

and each one gets displayed. But an SPA is a single page, so there's only one screen. That's why you use path routing,

like a router, to change what that screen shows.

\[

This covers the router basics plus qs, params, and history. I focused on the features you'll use most.

\]

## **\-Let's Try It in React Right Away**

**npx create-react-app \[your project name\]**

****yarn create react-app \[your project name\]****

Run one of these in the Command Prompt wherever you want the project.

Once the project is set up via CRA \[****create-react-app****\],

install the package that gives you routing -> **npm install react-router-dom**

**Then run it with npm start!!**

Once it's running, you'll see a list of files like the one below.

Open `index`. At first there will be a component called **<React.StrictMode>** wrapping `App`.

It's React's own tool for flagging potential problems, so it's fine to delete it.

Go ahead and delete it. Then add **<BrowserRouter>** as shown below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/23/img_1.webp)

```html
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import * as serviceWorker from './serviceWorker';

import {BrowserRouter}  from 'react-router-dom';      // this one

ReactDOM.render(
<BrowserRouter>  <App />
</BrowserRouter>
 ,
  document.getElementById('root')
);
```

We wrap it like this so that everything under the `App` component can use the router.

In App.js, create any two components you like. I kept it simple with AppA and AppB.

To set up routes like the ones below, you need separate JS files, so that's why we create them.

It's so we can show different things.

Write the code like this:

```html
import React from 'react';
import {Route , Link} from 'react-router-dom';
import AppA from './AppA';
import AppB from './AppB';

const App =()=>{

  return (
    <div>
		<ul>
			<li>
				<Link to="/">Nope</Link>
			</li>
			<li>
				<Link to="/AppB">Hi</Link>
			</li>
		</ul>

			<Route path="/" component={AppA} exact={true} />
			<Route path="/AppB" component={AppB} />
		</div>
  );
}
export default App;
```

We import `Link` and `Route` from the react-router-dom package we installed.

Give it a path and a component, and when the path matches, it renders that component.

`exact` asks whether it should only match the path exactly. I set it to `true`.

If you run it on port 3000, you'll see different components appear just by changing the path in the address bar.

But typing in the address bar yourself is a hassle, so the router has `Link`.

Following the code above, you can see that `Link` is what changes the path.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/23/img_2.webp)

Create AppA and AppB in the same directory as the App component.

![Screenshot 1](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/23/img_3.webp)

If you see this, it worked. The text at the bottom is just something I added for display.

`<Route path={\['/AbbA', '/AbbB'\]} component={AppB} />` lets two paths render the same component.

I've never once needed it.

**Now let's use params. This is a way to use the path in the address bar as a value.**

```html
import React from 'react';
import {Route , Link} from 'react-router-dom';
import AppA from './AppA';
import AppB from './AppB';
import Profile from  './Profile';

const App =()=>{

  return (
    <div>
					<ul>
					<li>
						<Link to="/AppA">A </Link>
					</li>
					<li>
						<Link to="/AppB">B </Link>
					</li>
						<li>
							<Link to="/profile/itzy">ITZY </Link>
						</li>
						<li>
						<Link to="/profile/me">Me</Link>
						</li>
					</ul>

				<Route path="/AppA" component={AppA} exact={true} />
				<Route path={['/BBB', '/AppB']} component={AppB} />
				<Route path="/profile/:username" component={Profile} />

		</div>
  );
}
export default App;
```

The parts to focus on are the new Profile JS file containing the code below, and the third route.

Writing `:username` means that if the path looks like `profile/whatever`,

it navigates there and passes `whatever` along as a parameter value. See `match` below.

```html
import React from 'react'

const data={
  itzy:{
    name:'Ryujin',
    description:'beauty'
  },
  me:{
    name:'yeol',
    description:'coding slave'
  }
};

const Profile =({match}) =>{

  const {username} = match.params;
  const profile = data[username];
  if(!profile){
    return <div>This user doesn't exist.</div>
  }

    return(
          <div>
            <h3>
              Name {username} description ({profile.description})
            </h3>
          </div>
    )
}

export default Profile;
```

The `match` object references the params when you use a Route component. It's not an object I made; `match`

is declared internally by the router.

I recommend running the code to understand it. The simpler the example, the more important it is to actually run it.

**Now let's use query strings. This is the second way to use the address bar as a value.**

**Once you've got this, I'd say you've covered the basics of using the address bar.**

I've kept just one easy example. We'll reuse the AppA component we made earlier.

```html
import React from 'react';
import {Route , Link} from 'react-router-dom';
import AppA from './AppA';
import AppB from './AppB';
import Profile from  './Profile';

const App =()=>{

  return (
    <div>
					<ul>
						<li>
						<Link to="/AppA?itzy=Ryujin">Me</Link>
						</li>
					</ul>

				<Route path="/AppA" component={AppA}  />

		</div>
  );
}
export default App;
```

If you've done any web development, this will be easy. You set a variable and value after the `?` and pass them along.

```html
import React from 'react';
import qs from 'qs'

const AppA =({location})=>{

  const query = qs.parse(location.search,{
    ignoreQueryPrefix:true   // Setting to drop the leading question mark
  });
  const showQs =query.itzy;
  return (
    <div>
        <h1>Itzy
        {showQs } is gorgeous. </h1>
    </div>
  );
}
export default AppA;
```

Install qs from npm. Like `match`, `location` is the object you use to get the query string.

We use `qs.parse` because if you don't parse it, the value from `location.search` comes through mangled.

[https://www.npmjs.com/package/qs](https://www.npmjs.com/package/qs) See the qs npm page for details!

If the value comes through correctly, you're done with qs.

**Finally, let's look at history and wrap up. It's a handy feature, so I'm including it.**

Add this one line to the existing App: `<Route path="/history" component={History}  />`

Then create a new JS file.

```html
import React , {Component} from 'react'

export default class History extends Component{

    handleGoBack=()=>{
      this.props.history.goBack();
    }
    handleGoHome=()=>{
      this.props.history.push('/');
    }

      componentDidMount(){
          this.unBlock = this.props.history.block('Ta-da');
      }

      componentWillUnmount(){
        if(this.unblock){
          this.unblock();
        }
      }

    render(){
      return(
        <div>
            <button onClick={this.handleGoBack}>Back</button>
            <button onClick={this.handleGoHome}>Home</button>
        </div>
      )
    }
}
```

There's a "go back." It's actually a pretty important feature. HTML changes pages, but an SPA is structured differently:

only the path changes, not the page itself like in HTML, so be grateful it exists when you use it.

I kept the code blocks as short as possible, so rather than explanations for understanding,

I hope the code itself makes understanding take less effort.
