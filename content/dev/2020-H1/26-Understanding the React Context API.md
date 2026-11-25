---
title: "Understanding the React Context API"
labels: ["TS","JS","react","context","Archive"]
published: true
date: 2020-06-15T15:12:26+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 26
tistoryUrl: "https://yeolceo.tistory.com/26"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","context","react"]
tistoryPostedAt: "2020-06-15 15:12:26"
language: en
bloggerPostId: "1013753328096067605"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/26/img.webp)

**This time I'll explain the Context API.**

Like Redux, it's for state management, but it's built into React.

Create a React project with create-react-app. Then

```html
import React, {createContext, useState} from 'react';

const ColorContext = createContext({color:'pink'});

export default ColorContext;
```

create a JS file like the one above.

Think of `createContext` as setting the default value. Here we initialized `color` to `pink` as an object.

```html
import React from 'react';
import ColorContext from './Color';

const App=()=>{

        return(
        	<div>
              <ColorContext.Consumer>
              { value=>(<div style={{width:'60px' ,height:'50px' , background: value.color }}/>)}
              </ColorContext.Consumer>
            </div>
        )
}
export default App;
```

To keep it simple, I put it straight into App. Using the context's `Consumer`,

you can get the `value` inside the component, much like `children`. Here, though,

we open another set of curly braces, render a component, and pass `value.color` into it.

This pattern is called Render Props.

Put simply, we grabbed a global variable and used it.

There's also a way to change that default value.

```html
import React from 'react';
import ColorContext from './Color';

const App=()=>{

        return(
        	<div>
            <ColorContext.Provider value={{color:'green' }}>
              <ColorContext.Consumer>
              { value=>(<div style={{width:'60px' ,height:'50px' , background: value.color }}/>)}
              </ColorContext.Consumer>
            </ColorContext.Provider>
          </div>
        )
}
export default App;
```

You use `Provider`. Notice that everything is a component based on the context from `createContext`.

`Provider` is a component that overrides the context's default value if there is one, and supplies one if there isn't.

That's already how to use it and how to change it. Because I kept it so simple, it might seem pointless

and not quite click yet.

For those readers, I've prepared the three files below.

**The first component.**

```html
import React from 'react'
import {ColorConsumer} from './Color'

const ColorBox =()=>{

  return (
        <ColorConsumer>
              { ({state}) =>(
                <>
                <div  style={{ width:'64px' , height:'64px', background: state.color}} />
                <div  style={{ width:'32px' , height:'32px', background: state.subcolor}} />
                </>
            )}
        </ColorConsumer>
  );
}
export default ColorBox;
```

We write a display-only component called `ColorBox`.

`ColorConsumer` works because we declared it with one of the following lines:

const ColorConsumer = ColorContext.Consumer;   // same as the line below

const {Consumer: ColorConsumer} = ColorContext; // same as the line above

In other words, it renders from `state` rather than `value` in the `ColorContext.Consumer` component.

**The second component.**

```html
import React, {createContext, useState} from 'react';

const ColorContext = createContext({

    state:{color: 'black' , subcolor: 'red'},
    action: {
        setColor: ()=>{},
        setSubcolor:()=>{}
    }
  });

const ColorProvider = ({children})=>{
      const [color , setColor] = useState('black');
      const [subcolor , setSubcolor] = useState('red');

      const value = {
        state:{color, subcolor},
        action: {setColor , setSubcolor}
      };

    return(
      <ColorContext.Provider value={value} >{children}</ColorContext.Provider>
    );
};

const {Consumer: ColorConsumer} = ColorContext;
export {ColorProvider, ColorConsumer};
export default ColorContext;
```

We use useState here. After setting the default value with `createContext`,

we create the Provider right below it. You could just use `value` as-is, but to separate things like Redux does,

I split `value` into `state` and `action`.

```html
import React, {useState} from 'react'
import ColorBox from './ColorBox';
import {ColorProvider , ColorConsumer} from './Color'

const App =()=>{

  return (
        <div>
          <ColorProvider>
          <div>
              <ColorBox />
          </div>

            <ColorConsumer>
              { ({action})=>(<button onClick={()=>{action.setColor('blue') }}>asdf</button>)}
            </ColorConsumer>
          </ColorProvider>
        </div>
      );
}
export default App;
```

**Finally, the part that renders everything.** This is where it all comes together in the App component.

Because `action` calls the useState setters, the values can be changed. That gives you something similar to Redux

in a simple way. For simple features, the performance gap with Redux isn't big.

Like hooks, Context has a lot of potential, so I think it's worth getting familiar with.
