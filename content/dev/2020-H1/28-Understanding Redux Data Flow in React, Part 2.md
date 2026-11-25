---
title: "Understanding Redux Data Flow in React, Part 2"
labels: ["TS","JS","react","Redux","Archive"]
published: true
date: 2020-06-17T12:18:06+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 28
tistoryUrl: "https://yeolceo.tistory.com/28"
tistoryCategory: "TS, JS/react"
tistoryTags: ["Redux","react","react"]
tistoryPostedAt: "2020-06-17 12:18:06"
language: en
bloggerPostId: "9035921466615808005"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/28/img_2.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/28/img_3.webp)

Thanks for following along so far. Now we'll build the counter's container.

Before that, take one more look at the flow. If it makes sense, move on.

## #Data Flow

You click a button (some feature) in a component (the View). The container, which manages the component's data,

then dispatches the clicked feature as an action. Each feature is identified by its action type. Once an action is dispatched,

the reducer (module) for that type carries it out. The result is saved in the store. When a new value is

saved in the store, the View re-renders.

![Source -> https://blog-kr.zoyi.co/channel-ios-redux/](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/28/img.webp)

## #Counter Container

The first thing to create is a folder. Make a containers folder under src.

If you now have components, containers, and modules folders, you're on track.

Looking at how the Counter component gets requested, you can tell that App won't request Counter directly;

it'll go through the container instead.

```html
import React from 'react';

import Counter from '../components/Counter';

const CounterContainer =()=>{  
  return <Counter/>;
};

export default CounterContainer;
```

Here we need the connect function that react-redux provides.

Add import {connect} from 'react-redux'; so you can use the code below.

```html
export default connect(  mapStateToProps , mapDispatchToProps  )(CounterContainer);
```

### **connect**

       **- mapStateToProps: a function that passes data held in the Redux store (where the reducer's initial or updated values live)**

                                            **to the component (CounterContainer) via props**

       **- mapDispatchToProps: a function that passes action creators to the component (CounterContainer) as props**

```html
import React from 'react';
import {connect} from 'react-redux';
import Counter from '../components/Counter';
import {increase, decrease } from '../modules/counter';

const CounterContainer =({number, increase , decrease})=>{    // Plug the container's functions into the counter's onClick handlers
  return (<Counter number={number} onIncrease={increase} onDecrease={decrease}/>);
};

const mapStateToProps();    // I removed the details here
const mapDispatchToProps();  // so we can cover them below.

export default connect(mapStateToProps , mapDispatchToProps)(CounterContainer);
```

Let's go through this slowly.

The container now calls the component. Since the container passes the functionality down as props,

the component is just a shell. That functionality comes from the action creators we built in the module.

Because the action creators are imported from the module and handed to the component as props through the container, the component

can use them.

Some of you might be wondering where number comes from.

That's what connect is for. We're about to call the container from App, and the last line of the code says we connect

state and dispatch to CounterContainer before exporting it.

That state is the reducer's state, where we set number to 0.

If the code above makes sense, keep going.

```html
import React from 'react';
import {connect} from 'react-redux';
import Counter from '../components/Counter';
import {increase, decrease } from '../modules/counter';

const CounterContainer =({number, increase , decrease})=>{    // Plug the container's functions into the counter's onClick handlers
  return (<Counter number={number} onIncrease={increase} onDecrease={decrease}/>);
};

const mapStateToProps = state =>({   // The reducer's state lives in the store; pull it in here
  number:state.counter.number,
});

const mapDispatchToProps = dispatch =>(
  {
    increase:()=>{dispatch(increase());} ,    // Action creators exported from the counter module
    decrease:()=>{dispatch(decrease());} ,
});

export default connect(mapStateToProps , mapDispatchToProps)(CounterContainer);
```

This part gets a bit detailed, so bear with me if the explanation runs long.

**mapStateToProps:** connect's first argument, mapStateToProps, receives the store's state as its first parameter, state.

The store's state is the value our counter module's reducer saved to the store.

That's why it's state.counter (the reducer's name).number.

**mapDispatchToProps:** I'll break it down like this: **1** increase:()=>{ **2**  dispatch( **3**  increase());}

1 is the key in the object we pass into <Counter number={number} onIncrease={increase} onDecrease={decrease}/>.

The same goes for number in the function above, and for increase and decrease. We create the object that gets passed to Counter and put

the data in it. Then, when you press the increase button in the Counter component,

it calls function 2. dispatch is also something Redux provides, as the parameter of connect's second argument function.

Calling dispatch means "run the reducer with this parameter (which has a type set)."

So 3 is the action creator. When dispatch runs,

increase, which we declared as export const increase =()=>({type:INCREASE });, sends its type to the reducer

as action. That's why the reducer checks action.type, and why the flow diagram shows dispatch

passing on to the action.

**CounterContainer:** once those two pieces are in place, CounterContainer runs. We've already set up number, increase, and decrease and received the data from Redux. That's why the component only has to handle the view.

We're almost there.

## #Wrapping Up: App.js

```html
import React from 'react';
import CounterContainer from './containers/CounterContainer'

const App =()=> {
  return (
    <div className="App">
        <CounterContainer />
    </div>
  );
}

export default App;
```

Render the counter container in the App component. I set mine to run on port 3100.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/28/img_1.webp)

Are +1 and -1 working for you too? Congrats!

I hope it all went smoothly. That wraps up this look at Redux.

You could add more libraries or tweak the structure, but I stuck to the parts that are easiest to understand

and used a counter as the example.

Whether it's MVC2 or Redux, a data layer is simple once you understand the structure.

If you're just starting to learn Redux, I hope this helped. Thanks for reading!
