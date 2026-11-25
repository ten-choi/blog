---
title: "React Hooks Made Easy!"
labels: ["TS","JS","react","Archive"]
published: true
date: 2020-06-11T09:43:07+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 19
tistoryUrl: "https://yeolceo.tistory.com/19"
tistoryCategory: "TS, JS/react"
tistoryTags: ["React","react","react","react"]
tistoryPostedAt: "2020-06-11 09:43:07"
language: en
bloggerPostId: "2594606696538078140"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/19/img.webp)

Hooks were introduced in React 16.8. They're built-in functions that let function components manage state,

something they couldn't do before.

**This post covers useState, useEffect, and useReducer.**

Let's create a new project with create-react-app!

**First up is useState, explained in exactly one page.**

Just like `setState` in class components, it re-renders when the value changes.

Here's how you use useState. I wrote a quick example, so let me walk you through it.

```html
import React , {useState} from 'react';

const App =()=>{

const [data , setData] = useState(0);

		return(
        	<div>
            	Value:{data}
            	<button onClick={()=>{setData(data+1); }} >Increase</button>
            </div>
        )
}

export default App;
```

Whatever you pass to useState, string or number, becomes the initial value of the first element in the array (here, `data`).

The second element (here, `setData`) is used like in the `onClick` below.

When you call `setData` with an argument, it assigns that value to `data` and re-renders the function component.

Once you try it, it feels simpler than `setState`. At least it did for me.

**Next is useEffect. It does two things, so it gets two pages.**

useEffect is a hook that runs some work every time the component renders.

Think of it as what `componentDidMount` and `componentDidUpdate` do in class components. Let's go through the code.

```html
import React , {useState , useEffect } from 'react';

const App =()=>{

const [data , setData] = useState(0);

useEffect(()=>{          // This is where useEffect is used
	console.log('Can you see it checking each render?');
});

		return(
        	<div>
            	Value:{data}
            	<button onClick={()=>{setData(data+1); }} >Increase</button>
            </div>
        )
}

export default App;
```

If you're running React on port 3000, open the developer tools.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/19/img_1.webp)

Press F12 and check the console.

You should see a console like the one below.

On the first render, and on every re-render triggered by `onClick`,

the `console.log` string will be printed.

It acts as both didMount and didUpdate.

But if you only want it on mount and don't want the didUpdate behavior, change the useEffect part of the code block like this:

```html
import React , {useState , useEffect } from 'react';

const App =()=>{

const [data , setData] = useState(0);

useEffect(()=>{        
	console.log('Can you see it checking each render?');
}, [] );  // Check here~!

		return(
        	<div>
            	Value:{data}
            	<button onClick={()=>{setData(data+1); }} >Increase</button>
            </div>
        )
}

export default App;
```

Just pass an empty array as useEffect's second parameter. Then you only get didMount.

Or, if you want **didUpdate** to run only when a specific value changes:

```html
import React , {useState , useEffect } from 'react';

const App =()=>{

const [data , setData] = useState(0);

useEffect(()=>{        
	console.log('Can you see it checking each render?');
}, [data] );  // Check here~!

		return(
        	<div>
            	Value:{data}
            	<button onClick={()=>{setData(data+1); }} >Increase</button>
            </div>
        )
}

export default App;
```

For example, if you put useState's first element into the array passed as useEffect's second parameter,

you'll see `console.log` fire every time that value changes. Very simple.

To wrap up, if you want to run something right before the component unmounts or updates again:

```html
useEffect(()=>{        
	console.log('Can you see it checking each render?');

    return ()=>{    // Use it like this.
    	console.log('cleanup = tidying up; think of it as wrapping things up before the next update'); 
    }
}, [] );
```

Just return a function like this. One book called it a "cleanup function."

**Congratulations. You've already mastered two of the main hooks.**

**Next is useReducer. It's easier to follow if you already know Redux. The difficulty goes up a notch.**

useReducer is a hook for when you need to update values in more varied ways depending on the component's situation than useState allows.

A reducer is a function that takes the current state and an action holding the information needed for the update, and returns a new value.

```html
import React , { useReducer} from 'react';

function reducer(state, action){
	switch(action.type){
    	case 'INCREASE':
        return{ value: state.value +1 };
        case 'DECREASE':
        return{ value: state.value -1 };
        default :
        return state;
    }
}

const App =()=>{

  const [state, dispatch]= useReducer(reducer, {value :0 } ) ;
		return(
        	<div>
  	         Value: {state.value}
            	<button onClick={()=>{ dispatch({type:'INCREASE'} ) }} >Increase</button>
                <button onClick={()=>{ dispatch({type:'DECREASE'} ) }} >Decrease</button>
                {console.log(useReducer())}
                {console.log(dispatch)}
          </div>
        );
}

export default App;
```

Create a reducer function that takes two parameters.

The first parameter is the state you'll use, and the second is the action carrying the type. Look at the `switch` in `function reducer` above:

it picks which case to run based on the type.

Now let's actually use it. First, declare useReducer.

If you've ever written `const { a } = this.state;`, you know it pulls the value `a` out of the state object.

I suspect the array above works on the same idea.

Declare `state` and `dispatch`. `state` holds the value and `dispatch` is the handler.

When you call `dispatch` with a type, it runs the reducer.

The reducer takes the initial `value`, handles it according to the type, and returns the result.

If you log to the console, you'll see it renders twice: the initial render and the useReducer render.

And each `dispatch` triggers two more renders.

It feels a bit different from useEffect, so use it accordingly.

If that all clicked right away, congratulations!
