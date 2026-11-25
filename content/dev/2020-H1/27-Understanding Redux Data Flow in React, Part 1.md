---
title: "Understanding Redux Data Flow in React, Part 1"
labels: ["TS","JS","react","Redux","Archive"]
published: true
date: 2020-06-17T10:30:58+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 27
tistoryUrl: "https://yeolceo.tistory.com/27"
tistoryCategory: "TS, JS/react"
tistoryTags: ["Redux","react","redux","react"]
tistoryPostedAt: "2020-06-17 10:30:58"
language: en
bloggerPostId: "8247502940592062471"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/27/img_3.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/27/img_4.webp)

**In this project, we'll look at Redux, the data layer most commonly used with React.**

**I'll explain it with a simple counter, since it's easy to follow. I find the Ducks pattern more convenient than the default pattern,**

**so that's what I used here.**

**\*The Ducks pattern means writing the reducer, the action type constants, and the action creators all in a single file.**

 **(In this project, we'll create a folder called modules.**

               **If there's a counter component, all three of those things go into one file.)**

* * *

## \# Data Structure and Flow

 Let me explain the basic structure first. I'll cover the details as we go.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/27/img.webp)

Component: handles everything you see on the page. It's just a shell for display.

Container: handles the functionality behind what the component shows. If the component has a +1 button,

               the container decides how +1 actually gets handled.

Module: carries out what the container decided and updates the data.

![Source -> https://blog-kr.zoyi.co/channel-ios-redux/](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/27/img_1.webp)

This is the data flow. You'll come back to it as things start to click.

The overall flow: you click a button (some feature) in a component (the View). The container, which manages the component's data,

then dispatches the clicked feature as an action. Each feature is identified by its action type. Once an action is dispatched,

the reducer (module) for that type carries it out. The result is saved in the store. When a new value is

saved in the store, the View re-renders.

※ Please make sure you roughly understand the explanation above before starting the project.

## \# Creating the Project

  Create a base app with create-react-app.

  Name the project redux-tutorial.

  npx create-react-app redux-tutorial

  To use Redux in the new project, add the libraries.

   npm install redux react-redux --save       \* --save records the libraries you installed in package.json.

  After removing the unnecessary parts from the default App.js, it looks like this:

```html
import React from 'react';

const App =()=> {
  return (
    <div className="App">

    </div>
  );
}

export default App;
```

## \# Preparing the Components

#### \- Counter Component

  First, create a components folder under src. The components folder will handle all the UI.

  Create the Counter component inside the components folder.

```html
import React from 'react';

const Counter =({number, onIncrease, onDecrease})=> {
  return (
    <div>
        <h1>{number}</h1>
        <button onClick={onIncrease}>+1</button>
        <button onClick={onDecrease}>-1</button>
    </div>
  );
}

export default Counter;
```

```html
import React from 'react';
import Counter from './components/Counter'

const App =()=> {
  return (
    <div className="App">
        <Counter number={0}/>
    </div>
  );
}

export default App;
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/27/img_2.webp)

If you see something like this, it worked.

The Counter component takes several props, but for now

we're only passing in number.

## \# Counter Module

Here's the path: './modules/counter'. Create a counter file in modules. As I mentioned earlier,

**the reducer, the action type "variables" (I call them variables to keep it simple, but let's declare them with const), and the action creators**

all go in here.

```html
// Action types

const INCREASE = 'counter/INCREASE';  // Define the types used for actions.
const DECREASE = 'counter/DECREASE';   

// Action creators

export const increase =()=>({type:INCREASE });  // With the types defined, export these.
export const decrease =()=>({type:DECREASE });  // These are what you pass to dispatch,
                                               // and the reducer below uses them in its cases.
const initialState={    // Just like it says: the initial state.
  number:0
}

// Reducer

function counter(state = initialState , action){

  switch (action.type) {  // Do whatever matches the type and update the data.
    case INCREASE:
    return{
          number:state.number+1
    };
    case DECREASE:
    return{
          number:state.number-1
    };
    default:
      return state;
  }
}
export default counter;
```

If your modules end up handling multiple components besides counter, you can merge them into one!

combineReducers literally combines reducers. Here we only pass in counter.

If you added an arbitrary component called test1, it would look like this. Since we're only using counter,

go ahead and remove the test1 parts.

```html
import {combineReducers} from 'redux';
import counter from  './counter';
import test1 from  './test1';

const rootReducer= combineReducers({
  counter , test1
});

export default rootReducer;
```

## \# Store

Let's look at index.js under src.

I only added the two commented lines below; everything else is the default. Let's add them now.

```html
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import * as serviceWorker from './serviceWorker';

import {createStore } from 'redux';   // This is the store. See the flow diagram.
import rootReducer from './modules'    // Load the reducer here. Since it's index, you can omit /index.

const store = createStore(rootReducer);
ReactDOM.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
  document.getElementById('root')
);

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: https://bit.ly/CRA-PWA
serviceWorker.unregister();
```

Keep checking the flow diagram. It's important to understand the data layer as you use it.

createStore does exactly what it says: it creates the store, the place where data is kept.

When declaring the store, we pass the reducer as an argument. It picks up initialState as the initial value.

Next, import Provider from react-redux. As the name suggests, it "provides" the store:

it's a component that re-renders whenever the store is initialized or receives a new value.

To use this component, you have to pass the store to it as a prop.

If you're getting Redux-related errors, stop for a moment and run npm install redux react-redux --save.

Those are the libraries you need to use Redux.

```html
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import * as serviceWorker from './serviceWorker';

import {createStore } from 'redux';
import rootReducer from './modules'
import {Provider} from 'react-redux'

const store = createStore(rootReducer);
ReactDOM.render(
  <Provider store={store} >
    <App />
  </Provider>
    ,
  document.getElementById('root')
);

serviceWorker.unregister();
```

And just like that, the initial store setup is done. Congrats!

[http://www.yeolceo.com/28](http://www.yeolceo.com/28)

If you've been following along, head over to the **next post**.
