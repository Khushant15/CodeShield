/**
 * taint/sources.js
 *
 * Defines regex patterns for identifying taint sources per language.
 * A taint source is any point where user-controlled data enters the program.
 *
 * Each entry captures the variable name being assigned from a tainted source
 * via named capture group `(?<varName>...)`.
 */

'use strict';

/**
 * @type {Record<string, {pattern: RegExp, label: string}[]>}
 */
const SOURCES = {
  javascript: [
    // req.body.x, req.body['x'], req.body
    { pattern: /(?:const|let|var)\s+(?<varName>\w+)\s*=\s*req\.body(?:\.\w+|\[['"][^'"]+['"]\])?/,   label: 'HTTP request body'  },
    { pattern: /(?:const|let|var)\s+(?<varName>\w+)\s*=\s*req\.query(?:\.\w+|\[['"][^'"]+['"]\])?/,  label: 'HTTP query param'   },
    { pattern: /(?:const|let|var)\s+(?<varName>\w+)\s*=\s*req\.params(?:\.\w+|\[['"][^'"]+['"]\])?/, label: 'HTTP route param'   },
    { pattern: /(?:const|let|var)\s+(?<varName>\w+)\s*=\s*req\.headers(?:\.\w+|\[['"][^'"]+['"]\])?/,label: 'HTTP header'        },
    // Destructuring: const { id, name } = req.body
    { pattern: /(?:const|let|var)\s+\{[^}]*\}\s*=\s*req\.(?:body|query|params)/,                     label: 'HTTP request (destructured)' },
    // process.env  (env-injected but still taint source if user-influenced config)
    { pattern: /(?:const|let|var)\s+(?<varName>\w+)\s*=\s*process\.env\.\w+/,                         label: 'Environment variable' },
    // document.cookie, localStorage
    { pattern: /(?:const|let|var)\s+(?<varName>\w+)\s*=\s*document\.cookie/,                          label: 'Browser cookie'     },
    { pattern: /(?:const|let|var)\s+(?<varName>\w+)\s*=\s*localStorage\.getItem\s*\(/,               label: 'localStorage'        },
  ],

  python: [
    // Flask: request.args.get('x'), request.form['x']
    { pattern: /(?<varName>\w+)\s*=\s*request\.args(?:\.get\s*\([^)]+\)|\[['"][^'"]+['"]\])/,         label: 'Flask query arg'    },
    { pattern: /(?<varName>\w+)\s*=\s*request\.form(?:\.get\s*\([^)]+\)|\[['"][^'"]+['"]\])/,         label: 'Flask form data'    },
    { pattern: /(?<varName>\w+)\s*=\s*request\.json(?:\.get\s*\([^)]+\)|\[['"][^'"]+['"]\])?/,       label: 'Flask JSON body'    },
    { pattern: /(?<varName>\w+)\s*=\s*request\.get_json\s*\(\s*\)/,                                   label: 'Flask JSON body'    },
    { pattern: /(?<varName>\w+)\s*=\s*request\.headers\.get\s*\(/,                                    label: 'HTTP header'        },
    // Django: request.GET['x'], request.POST['x']
    { pattern: /(?<varName>\w+)\s*=\s*request\.GET(?:\.get\s*\([^)]+\)|\[['"][^'"]+['"]\])/,          label: 'Django GET param'   },
    { pattern: /(?<varName>\w+)\s*=\s*request\.POST(?:\.get\s*\([^)]+\)|\[['"][^'"]+['"]\])/,         label: 'Django POST param'  },
    // Built-in input()
    { pattern: /(?<varName>\w+)\s*=\s*input\s*\(/,                                                    label: 'stdin input()'      },
    // Environment
    { pattern: /(?<varName>\w+)\s*=\s*os\.environ(?:\.get\s*\([^)]+\)|\[['"][^'"]+['"]\])/,           label: 'Environment variable' },
    // sys.argv
    { pattern: /(?<varName>\w+)\s*=\s*sys\.argv\s*\[/,                                               label: 'CLI argument'       },
  ],

  java: [
    // HttpServletRequest: getParameter, getHeader, getInputStream
    { pattern: /(?:String\s+|var\s+)?(?<varName>\w+)\s*=\s*\w+\.getParameter\s*\(/,                   label: 'HTTP request parameter' },
    { pattern: /(?:String\s+|var\s+)?(?<varName>\w+)\s*=\s*\w+\.getHeader\s*\(/,                      label: 'HTTP header'             },
    { pattern: /(?:String\s+|var\s+)?(?<varName>\w+)\s*=\s*\w+\.getInputStream\s*\(\s*\)/,            label: 'HTTP input stream'       },
    // Spring: @RequestParam, @PathVariable, @RequestBody (annotation-driven — flag the method param)
    { pattern: /@(?:RequestParam|PathVariable|RequestBody)\s+\w+\s+(?<varName>\w+)/,                   label: 'Spring MVC input'        },
    // System.getenv
    { pattern: /(?:String\s+|var\s+)?(?<varName>\w+)\s*=\s*System\.getenv\s*\(/,                      label: 'Environment variable'    },
    // Scanner reading stdin
    { pattern: /(?<varName>\w+)\s*=\s*\w+\.nextLine\s*\(\s*\)/,                                       label: 'Console input'           },
  ],
};

module.exports = { SOURCES };
