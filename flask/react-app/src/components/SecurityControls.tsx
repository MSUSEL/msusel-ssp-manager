import React, { useState, useMemo } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@radix-ui/react-tabs';
import controls from '../data/NIST_SP-800-53_rev5_catalog.json';
import enrichedControls from '../data/enriched_800_53_controls.json';
import './SecurityControls.css';

interface NISTControl {
  id: string;
  title: string;
  statements: string[];
  guidance: string;
}

interface EnrichedControl {
  control_id: string;
  title: string;
  family: string;
  purpose: string;
  description: string;
  implementation_guidance: string[];
  assessment_objectives: string;
}

const SecurityControls: React.FC = () => {
  const [expandedControl, setExpandedControl] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedFamily, setSelectedFamily] = useState<string>('');

  const families = useMemo(() => {
    const uniqueFamilies = new Set(enrichedControls.map(control => control.family));
    return Array.from(uniqueFamilies).sort();
  }, []);

  const findEnrichedControl = (controlId: string): EnrichedControl | undefined => {
    return enrichedControls.find(control => control.control_id.toLowerCase() === controlId.toLowerCase());
  };

  const filteredControls = useMemo(() => {
    return controls.filter((control: NISTControl) => {
      const enrichedControl = findEnrichedControl(control.id);
      const matchesSearch = 
        control.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        control.title.toLowerCase().includes(searchTerm.toLowerCase());
      
      if (selectedFamily && enrichedControl) {
        return matchesSearch && enrichedControl.family === selectedFamily;
      }
      return matchesSearch;
    });
  }, [searchTerm, selectedFamily]);

  const toggleControl = (controlId: string) => {
    setExpandedControl(expandedControl === controlId ? null : controlId);
  };

  return (
    <div className="controls-container">
      <div className="controls-header">
        <div className="search-filter-container">
          <input
            type="text"
            placeholder="Search by control ID or title..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
          <select
            value={selectedFamily}
            onChange={(e) => setSelectedFamily(e.target.value)}
            className="family-select"
          >
            <option value="">All Families</option>
            {families.map(family => (
              <option key={family} value={family}>{family}</option>
            ))}
          </select>
        </div>
        {searchTerm && (
          <div className="search-results-count">
            Found {filteredControls.length} controls
          </div>
        )}
      </div>

      {filteredControls.map((control: NISTControl) => {
        const enrichedControl = findEnrichedControl(control.id);
        
        return (
          <div key={control.id} className="control-section">
            <div 
              className={`control-header ${expandedControl === control.id ? 'expanded' : ''}`}
              onClick={() => toggleControl(control.id)}
            >
              <div className="control-title">
                <span className="control-family">{enrichedControl?.family}</span>
                <h2>{control.id} - {control.title}</h2>
              </div>
              <span className="expand-icon">{expandedControl === control.id ? '−' : '+'}</span>
            </div>
            
            {expandedControl === control.id && (
              <div className="control-details">
                <Tabs defaultValue="overview">
                  <TabsList>
                    <TabsTrigger value="overview">Overview</TabsTrigger>
                    <TabsTrigger value="statements">Control Statements</TabsTrigger>
                    <TabsTrigger value="implementation">Implementation</TabsTrigger>
                    <TabsTrigger value="assessment">Assessment</TabsTrigger>
                  </TabsList>

                  <TabsContent value="overview">
                    <div className="overview-section">
                      <h3>Purpose</h3>
                      <p>{enrichedControl?.purpose}</p>
                      <h3>Description</h3>
                      <p>{enrichedControl?.description}</p>
                    </div>
                  </TabsContent>

                  <TabsContent value="statements">
                    <div className="statements-section">
                      <h3>Control Statements</h3>
                      <ul>
                        {control.statements.map((statement, index) => (
                          <li key={index}>{statement}</li>
                        ))}
                      </ul>
                      <h3>Additional Guidance</h3>
                      <p>{control.guidance}</p>
                    </div>
                  </TabsContent>

                  <TabsContent value="implementation">
                    <div className="implementation-section">
                      <h3>Implementation Guidance</h3>
                      <ul className="implementation-checklist">
                        {enrichedControl?.implementation_guidance.map((guide, index) => (
                          <li key={index}>
                            <input type="checkbox" id={`check-${control.id}-${index}`} />
                            <label htmlFor={`check-${control.id}-${index}`}>{guide}</label>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </TabsContent>

                  <TabsContent value="assessment">
                    <div className="assessment-section">
                      <h3>Assessment Objectives</h3>
                      <p>{enrichedControl?.assessment_objectives}</p>
                    </div>
                  </TabsContent>
                </Tabs>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default SecurityControls;
