import React from 'react';
import ReactMarkdown from 'react-markdown';

const markdownContent = `
# Documentation

## Overview

This is a sample documentation view in a React application.

### Features

- **Markdown Support**: Write your documentation using Markdown.
- **Easy Integration**: Simply import your Markdown content and render it.
- **Custom Styling**: Style your documentation using standard CSS.

## Getting Started

To get started with this application, follow these steps:

1. Clone the repository.
2. Install the dependencies using \`npm install\`.
3. Run the application with \`npm start\`.

## Code Example

Here’s a simple code example:

\`\`\`typescript
import React from 'react';

const HelloWorld = () => {
  return <h1>Hello, world!</h1>;
};

export default HelloWorld;
\`\`\`

## Conclusion

Using \`react-markdown\`, you can easily render Markdown content in your React application for documentation purposes.
`;

const Documentation = () => {
  return (
    <div className="documentation">
      <ReactMarkdown>{markdownContent}</ReactMarkdown>
    </div>
  );
};

export default Documentation;
