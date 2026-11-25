---
title: "React Hooks Made Easy, Part 2!"
labels: ["TS","JS","react","Archive"]
published: true
date: 2020-06-11T12:39:27+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 20
tistoryUrl: "https://yeolceo.tistory.com/20"
tistoryCategory: "TS, JS/react"
tistoryTags: ["React","react","react","react"]
tistoryPostedAt: "2020-06-11 12:39:27"
language: en
bloggerPostId: "4113427759734154764"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/20/img.webp)

Let's keep using hooks the easy way. I find it easiest to run the code first and then take it apart.

We'll start with a quick review of the reducer from last time.

**useReducer: a variation on the classic**

```html
import React, {useReducer }from 'react';

function reducer(state, action){

  console.log(`action name   ->${action.name}`);
  console.log(`action value  ->${action.value}`);
    return{
      ...state,
      [action.name]:action.value
    };
}
const App =()=>{

  const [state, dispatch]= useReducer(reducer, {user:'' , nickname:''});
  const {user , nickname} = state;

  const onChange =e=>{
    console.log(e.target);
    dispatch(e.target);
  }
  return (
    <div>
        <input name="user" value={user} onChange={onChange} /> <br />
        <input name="nickname" value={nickname} onChange={onChange} /> <br />
          <b>Name:</b>{user}<br />
          <b>Nickname:</b>{nickname}
    </div>
  );
}

export default App;
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/20/img_1.webp)

The useReducer and dispatch pattern is the same as before. Let's focus on `onChange` first.

We grab the value with `e.target`. As you can see in the console, the whole `<input` element gets printed.

So we're dispatching the input element itself as the parameter. How does that work?

What matters on the input are `name` and `value`. Think of it as putting `name` and `value` where the action's `type` used to go.

Then we return, just like we did with the `switch`. We spread `...state` first to keep the original state immutable.

After that, setting `[action.name]` to `action.value` works exactly like the reducer I explained last time.

The `switch`/`case` was just a way of picking what to return anyway.

In the end, you give each input the same `name` as the initial state key and assign the value.

```html
switch(action.type){
    	case 'INCREASE':
        return{ value: state.value +1 };
```

Running it and comparing against the console makes this much easier to understand.

**useMemo is a hook that recomputes a value only when the values you specify change.**

```html
import React, {useState , useMemo }from 'react';

const getAverage = numbers =>{
		console.log('Calculating the average...');
		if(numbers.length ===0)return 0;
		const sum = numbers.reduce((a,b)=>a+b);
		return sum/numbers.length;
}

const App =()=>{

	const [list, setList] =useState([]);
	const [number, setNumber]= useState('');

	const onChange =e=>{
		setNumber(e.target.value);  };
	const onInsert=e=>{
		const nextList = list.concat(parseInt(number));
		setList(nextList);
		setNumber('');
	}
	const avg = useMemo(()=>getAverage(list),[list]); // Pay attention here

  return (
    <div>
			<input value = {number} onChange = {onChange} />
			<button onClick={onInsert}>Add</button>
				<ul>
					{list.map((value, index)=>(
						<li key={index}>{value}</li>
					))}
				</ul>
				<div>
					Average : {avg}
				</div>
		</div>
  );
}
export default App;
```

Try removing the useMemo line and see how the console output changes.

The idea is simple. We create an array called `list`, and when an input is finished and added to `list`, the list changes,

so that's when we update the output value `avg`.

In the `reduce` call above, the first argument starts as the first element and the second argument walks through the rest of `list`.

True to its name, `reduce` boils the array down to a single value: `a` is the running total, and `b` is each value in `list`, added on

until every value has been summed.

Another way to understand the structure is to sprinkle in `console.log('debug 1')`, `console.log('debug 2')`, and so on.

**Finally, useRef. It does the same thing as `ref` in class components.**

```html
useRef

    	const element = useRef(null);
		element.current.focus();
		ref={element}
```

It's so easy to use that I kept the example tiny.

Import useRef in the code above. Then set `ref` on the input, and inside `ref`, as in the code block,

put the variable you created with useRef.

Add `element.current.focus();` at the very end of the insert code. As soon as an item is added, it runs

and you'll see the cursor land back in that input element.

Those are the hooks I find most useful. I hope this helped.
