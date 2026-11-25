---
title: "How to Build an Electron App and Turn It into an Installer"
labels: ["ETC","Electron","Installer","build","builder","Archive"]
published: true
date: 2021-08-02T16:35:45+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 104
tistoryUrl: "https://yeolceo.tistory.com/104"
tistoryCategory: "ETC/Electron"
tistoryTags: ["Installer","build","builder","Electron"]
tistoryPostedAt: "2021-08-02 16:35:45"
language: en
bloggerPostId: "3446085168787141758"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/104/img.webp)

## Building the App

I'm using Node 14.17.1.

First, get the Electron project you want to build ready.

Install the library below globally (-g). It's the Electron builder library.

```html
npm install -g electron-builder
```

Let's look at the JSON file.

In scripts, you specify which platform to target when building.

You also set the path to the image used for the packaged file. Apart from scripts and build, you don't need to touch the JSON.

```html
{
  "name": "project-name",

  "version": "1.0.0",

  "description": "Description of your Electron app",

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
      "icon": "path to the packaged file's icon image"
    }
  }
}
```

Now running npm run build:win64 builds the Electron app for 64-bit Windows.

## Creating the Installer

Let's turn the build output into an installer.

[https://wixtoolset.org/releases/](https://wixtoolset.org/releases/)

Go to this page, click the download link, and find what's shown in the image below. Download the exe file and run it.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/104/img_1.webp)

Once it launches, install it. A WiX folder will be created under Program Files (x86).

Add that directory's bin path to your environment variables.

If typing candle in CMD prints anything at all, the environment variable is set up correctly.

Install the WiX installer library from npm.

 **npm install electron-wix-msi --save-dev** 

(This library requires Python to be installed and on your PATH.)

electron-wix-msi is written mostly in ES6 syntax, so install Babel to avoid runtime errors.

**npm install --save-dev babel-cli babel-preset-env babel-preset-stage-3**

To apply Babel, create a file called .babelrc in the project root and add the following.

```html
{
    "presets": ["env", "stage-3"]
}
```

Now create the file that builds the installer: builder.js.

```html
import { MSICreator } from 'electron-wix-msi';

// MSI file creator
const msiCreator = new MSICreator({
  appDirectory: 'the built (unpacked) Electron directory',
  description: 'description',
  exe: 'name of the exe file inside the built Electron directory',
  name: 'name',
  manufacturer: 'manufacturer',
  version: '1.1.0',
  outputDirectory: 'directory to save the installer to',
  ui : {
    chooseDirectory : true
  },
  shortcutName : 'shortcut name'
});

// create and compile
msiCreator.create().then(function(){
    msiCreator.compile();
})
```

This is the builder file that turns the Electron app into an MSI installer.

Add an installer entry to scripts. builder.js is the file we just made, and babel-node means it runs with the Babel setup from earlier.

```html
"scripts": {
    "build_installer": "babel-node builder.js"
 }
```

npm run build\_installer 

This creates the MSI file. Use it when you need to install the app somewhere else.

If you use an env file, put it in the build directory after building, then create the installer.

Here's the blog post I referred to: [https://lts0606.tistory.com/475](https://lts0606.tistory.com/475)

Happy coding.
