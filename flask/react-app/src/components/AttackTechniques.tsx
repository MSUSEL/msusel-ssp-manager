/*import React, { useEffect, useRef } from 'react';

const AttackTechniques: React.FC = () => {
  const iframeRef = useRef<HTMLIFrameElement>(null);

  useEffect(() => {
    if (iframeRef.current) {
      iframeRef.current.src = '/api/getGraph/graph';
    }
  }, []);

  return (
    <div>
      <iframe ref={iframeRef} width="100%" height="600px" title="Graph" />
    </div>
  );
};

export default AttackTechniques;*/



/* Este sirve. Solo recibe un json string */
/* import React, { useEffect, useState } from 'react';
import { Box, Heading, Text } from '@radix-ui/themes';

const AttackTechniques: React.FC = () => {
  const [data, setData] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/getGraph/graph')
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then(jsonData => setData(jsonData.message))
      .catch(error => {
        console.error('Error fetching data:', error);
        setData('Error fetching data');
      });
  }, []);

  return (
    <Box as="div" className="main-content">
      <Text size="3">Attack Techniques Graph</Text>
      {data ? <Box>{data}</Box> : <Box>Loading...</Box>}
    </Box>
  );
};

export default AttackTechniques;*/





/*import React, { useEffect, useState } from 'react';
import { Box, Text } from '@radix-ui/themes';

const AttackTechniques: React.FC = () => {
  const [htmlContent, setHtmlContent] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/getGraph/graph')
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.text();
      })
      .then(htmlData => setHtmlContent(htmlData))
      .catch(error => {
        console.error('Error fetching data:', error);
        setHtmlContent('<p>Error fetching data</p>');
      });
  }, []);

  return (
    <Box as="div" className="main-content">
      <Text size="3">Attack Techniques Graph</Text>
      {htmlContent ? (
        <Box dangerouslySetInnerHTML={{ __html: htmlContent }} />
      ) : (
        <Box>Loading...</Box>
      )}
    </Box>
  );
};

export default AttackTechniques;*/





/*import React, { useEffect, useState } from 'react';
import { Box, Text } from '@radix-ui/themes';

const AttackTechniques: React.FC = () => {
  const [htmlContent, setHtmlContent] = useState<string | null>(null);

  useEffect(() => {
    console.log('Fetching HTML content from /api/getGraph/graph');
    
    fetch('/api/getGraph/graph')
      .then(response => {
        console.log('Received response:', response);
        
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return response.text();
      })
      .then(htmlData => {
        console.log('HTML data fetched successfully');
        setHtmlContent(htmlData);
      })
      .catch(error => {
        console.error('Error fetching data:', error);
        setHtmlContent('<p>Error fetching data</p>');
      });
  }, []);

  console.log('Rendering component with htmlContent:', htmlContent);

  return (
    <Box as="div" className="main-content">
      <Text size="3">Attack Techniques Graph</Text>
      {htmlContent ? (
        <Box dangerouslySetInnerHTML={{ __html: htmlContent }} />
      ) : (
        <Box>Loading...</Box>
      )}
    </Box>
  );
};

export default AttackTechniques;*/



/*import React, { useEffect, useState } from 'react';

const AttackTechniques: React.FC = () => {
  const [htmlContent, setHtmlContent] = useState<string>('');

  useEffect(() => {
    const fetchHtml = async () => {
      try {
        console.log('Starting to fetch HTML content...');

        const response = await fetch('/api/getGraph/grap'); // Replace with your Flask endpoint
        console.log(`Received response with status: ${response.status}`);

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const text = await response.text(); // Fetch as text instead of JSON
        console.log('HTML content successfully fetched:', text.substring(0, 100)); // Log the first 100 characters of the HTML

        setHtmlContent(text);
      } catch (error) {
        console.error('Error fetching HTML:', error);
      }
    };

    fetchHtml();
  }, []);

  return (
    <div>
      <h1>Attack Techniques</h1>
      <div dangerouslySetInnerHTML={{ __html: htmlContent }} />
    </div>
  );
};

export default AttackTechniques;
*/


/*
import React, { useEffect, useState } from 'react';
import { Box, Heading, Text } from '@radix-ui/themes';

const AttackTechniques: React.FC = () => {
  const [data, setData] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/getGraph/graph')
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.text();
      })
      .then(data => setData(data))
      .catch(error => {
        console.error('Error fetching data:', error);
        setData('Error fetching data');
      });
  }, []);

  return (
    <Box as="div" className="main-content">
      <Text size="3">Attack Techniques Graph</Text>
      {data ? <Box>{data}</Box> : <Box>Loading...</Box>}
    </Box>
  );
};

export default AttackTechniques;*/




//Este hace fetch, pero no render
/*import React, { useEffect, useState } from 'react';

const AttackTechniques: React.FC = () => {
  const [htmlContent, setHtmlContent] = useState<string>('');

  useEffect(() => {
    const fetchHtml = async () => {
      try {
        console.log('Starting to fetch HTML content...');

        const response = await fetch('/api/getGraph/graph'); // Use the service name as hostname
        console.log(`Received response with status: ${response.status}`);

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const text = await response.text();
        console.log('HTML content successfully fetched:', text.substring(0, 100)); // Log the first 100 characters

        setHtmlContent(text);
      } catch (error) {
        console.error('Error fetching HTML:', error);
      }
    };

    fetchHtml();
  }, []);

  return (
    <div>
      <h1>Attack Techniques</h1>
      <div dangerouslySetInnerHTML={{ __html: htmlContent }} />
    </div>
  );
};

export default AttackTechniques;*/





/*
import React, { useEffect, useState } from 'react';

const AttackTechniques: React.FC = () => {
  const [htmlUrl, setHtmlUrl] = useState<string>('');

  useEffect(() => {
    const fetchHtml = async () => {
      try {
        console.log('Starting to fetch HTML content...');

        // Replace with your Flask endpoint URL
        const response = await fetch('/api/getGraph/graph');
        console.log(`Received response with status: ${response.status}`);

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        // Assume graph.html is served directly and set URL for iframe
        setHtmlUrl('http://flask-backend:5000/api/getGraph/graph');
      } catch (error) {
        console.error('Error fetching HTML:', error);
      }
    };

    fetchHtml();
  }, []);

  return (
    <div>
      <h1>Attack Techniques</h1>
      {htmlUrl ? (
        <iframe
          src={htmlUrl}
          style={{ width: '100%', height: '600px', border: 'none' }}
          title="PyVis Graph"
        ></iframe>
      ) : (
        <p>Loading graph...</p>
      )}
    </div>
  );
};

export default AttackTechniques;*/


//Este sirve
/*import React, { useEffect, useState } from 'react';

const AttackTechniques: React.FC = () => {
  const [htmlUrl, setHtmlUrl] = useState<string>('');

  useEffect(() => {
    const fetchHtml = async () => {
      try {
        console.log('Starting to fetch HTML content...');

        const response = await fetch('/api/getGraph/graph'); // Adjust URL as needed
        console.log(`Received response with status: ${response.status}`);

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        // Assuming the HTML is saved in a publicly accessible directory
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        setHtmlUrl(url);
      } catch (error) {
        console.error('Error fetching HTML:', error);
      }
    };

    fetchHtml();
  }, []);

  const iframeStyle = {
    width: '100%',
    height: '100%',
    border: '1px solid #ddd', // Optional: border styling
    boxSizing: 'border-box',
    overflow: 'hidden' // Hides any overflow to keep the content tidy
  };

  return (
    <div>
      <h2> Attack Techniques</h2>
      {htmlUrl ? (
        <iframe
        src={htmlUrl}
        //style={{ width: '100%', height: '100%', border: '2px solid red' }} // Increase height as needed
        style={iframeStyle}
        loading="lazy"
        title="Pyvis Graph"
      />      
      ) : (
        <p>Loading graph...</p>
      )}
    </div>
  );
};

export default AttackTechniques;*/






import React, { useEffect, useState } from 'react';

const AttackTechniques: React.FC = () => {
  const [htmlUrl, setHtmlUrl] = useState<string>('');

  useEffect(() => {
    const fetchHtml = async () => {
      try {
        console.log('Starting to fetch HTML content...');

        const response = await fetch('/api/getGraph/graph'); // Adjust URL as needed
        console.log(`Received response with status: ${response.status}`);

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        setHtmlUrl(url);
      } catch (error) {
        console.error('Error fetching HTML:', error);
      }
    };

    fetchHtml();
  }, []);

  const containerStyle = {
    width: '100%',
    height: 'calc(100vh - 100px)', // Adjust the height as needed to fit your layout
    border: '1px solid #ddd', // Optional: border styling
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center'
  };

  const iframeStyle = {
    width: '95%', // Adjust the width as needed
    height: '95%', // Adjust the height as needed
    border: '1px solid #ddd', // Optional: border styling
    boxSizing: 'border-box',
    overflow: 'hidden' // Hides any overflow to keep the content tidy
  };

  return (
    <div style={containerStyle}>
      <h2> Attack Techniques</h2>
      {htmlUrl ? (
        <iframe
          src={htmlUrl}
          style={iframeStyle}
          loading="lazy"
          title="Pyvis Graph"
        />
      ) : (
        <p>Loading graph...</p>
      )}
    </div>
  );
};

export default AttackTechniques;
